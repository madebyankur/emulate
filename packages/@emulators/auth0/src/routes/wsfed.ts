import { createSign, createHash, randomUUID } from "node:crypto";
import type { RouteContext } from "@emulators/core";
import { renderFormPostPage } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { nodeKeys } from "../keys.js";
import { issuerFromBaseUrl } from "../helpers.js";
import { renderUniversalLogin, SERVICE_LABEL } from "./ui.js";
import { recordLog } from "../events.js";

// Minimal-but-real WS-Federation IdP. /wsfed/:clientId (wsignin1.0) renders
// Universal Login then form-POSTs a wresult containing a signed SAML 1.1
// assertion to the wreply (client callback). Shares the RS256 signing key with
// the rest of the emulator so the assertion verifies against the metadata cert.

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

async function buildSignature(signedElementXml: string, referenceId: string, certB64: string): Promise<string> {
  const digest = createHash("sha256").update(signedElementXml).digest("base64");
  const signedInfo =
    `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
    `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
    `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>` +
    `<ds:Reference URI="#${referenceId}">` +
    `<ds:Transforms>` +
    `<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>` +
    `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>` +
    `</ds:Transforms>` +
    `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
    `<ds:DigestValue>${digest}</ds:DigestValue>` +
    `</ds:Reference></ds:SignedInfo>`;
  const { privateKey } = await nodeKeys();
  const signatureValue = createSign("RSA-SHA256").update(signedInfo).sign(privateKey).toString("base64");
  return (
    `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
    signedInfo +
    `<ds:SignatureValue>${signatureValue}</ds:SignatureValue>` +
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `</ds:Signature>`
  );
}

export function wsfedRoutes({ app, store, baseUrl }: RouteContext): void {
  const as = getAuth0Store(store);
  const issuer = issuerFromBaseUrl(baseUrl);

  app.get("/wsfed/:clientId", (c) => {
    const clientId = c.req.param("clientId");
    const action = c.req.query("wa") ?? "wsignin1.0";
    if (action === "wsignout1.0") {
      const reply = c.req.query("wreply");
      return reply ? c.redirect(reply, 302) : c.text("Signed out");
    }
    const client = as.clients.findOneBy("client_id", clientId);
    const wreply = c.req.query("wreply") ?? client?.callbacks[0] ?? "";
    const wctx = c.req.query("wctx") ?? "";
    const wtrealm = c.req.query("wtrealm") ?? clientId;
    return c.html(
      renderUniversalLogin(
        as.users.all(),
        client?.name ?? "WS-Fed App",
        { redirect_uri: wreply, state: wctx, client_id: clientId, audience: wtrealm },
        `/wsfed/${clientId}/callback`,
      ),
    );
  });

  app.post("/wsfed/:clientId/callback", async (c) => {
    const clientId = c.req.param("clientId");
    const body = await c.req.parseBody();
    const userRef = typeof body.user_ref === "string" ? body.user_ref : "";
    const wreply = typeof body.redirect_uri === "string" ? body.redirect_uri : "";
    const wctx = typeof body.state === "string" ? body.state : "";
    const wtrealm = typeof body.audience === "string" ? body.audience : clientId;
    const user = as.users.findOneBy("user_id", userRef);
    if (!user || !wreply) return c.text("Invalid WS-Fed login", 400);

    const assertion = await buildSaml11Assertion({ issuer, audience: wtrealm, user });
    const wresult =
      `<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">` +
      `<t:RequestedSecurityToken>${assertion}</t:RequestedSecurityToken>` +
      `<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">` +
      `<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>${xmlEscape(wtrealm)}</wsa:Address></wsa:EndpointReference>` +
      `</wsp:AppliesTo></t:RequestSecurityTokenResponse>`;
    await recordLog(store, { type: "ssa", description: "WS-Fed SSO", clientId, userId: user.user_id });
    return c.html(renderFormPostPage(wreply, { wa: "wsignin1.0", wresult, wctx }, SERVICE_LABEL));
  });

  app.get("/wsfed/FederationMetadata/2007-06/FederationMetadata.xml", async (c) => {
    const { publicDerB64 } = await nodeKeys();
    const md =
      `<?xml version="1.0"?>` +
      `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${xmlEscape(issuer)}">` +
      `<RoleDescriptor xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706">` +
      `<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
      `<X509Data><X509Certificate>${publicDerB64}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
      `</RoleDescriptor></EntityDescriptor>`;
    return c.body(md, 200, { "Content-Type": "application/xml" });
  });
}

async function buildSaml11Assertion(args: {
  issuer: string;
  audience: string;
  user: { user_id: string; email: string; name: string };
}): Promise<string> {
  const { issuer, audience, user } = args;
  const { publicDerB64 } = await nodeKeys();
  const assertionId = `_${randomUUID().replace(/-/g, "")}`;
  const now = new Date(Date.now()).toISOString();
  const notOnOrAfter = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  const body =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="${assertionId}" Issuer="${xmlEscape(issuer)}" IssueInstant="${now}">` +
    `<saml:Conditions NotBefore="${now}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestrictionCondition><saml:Audience>${xmlEscape(audience)}</saml:Audience></saml:AudienceRestrictionCondition>` +
    `</saml:Conditions>` +
    `<saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="${now}">` +
    `<saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${xmlEscape(user.email)}</saml:NameIdentifier></saml:Subject>` +
    `</saml:AuthenticationStatement>` +
    `<saml:AttributeStatement>` +
    `<saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${xmlEscape(user.email)}</saml:NameIdentifier></saml:Subject>` +
    `<saml:Attribute AttributeName="emailaddress" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"><saml:AttributeValue>${xmlEscape(user.email)}</saml:AttributeValue></saml:Attribute>` +
    `<saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"><saml:AttributeValue>${xmlEscape(user.name)}</saml:AttributeValue></saml:Attribute>` +
    `</saml:AttributeStatement>`;
  const signature = await buildSignature(`${body}</saml:Assertion>`, assertionId, publicDerB64);
  return `${body}${signature}</saml:Assertion>`;
}
