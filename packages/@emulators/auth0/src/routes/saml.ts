import { createSign, createHash, randomUUID } from "node:crypto";
import type { RouteContext } from "@emulators/core";
import { renderFormPostPage } from "@emulators/core";
import { getAuth0Store } from "../store.js";
import { nodeKeys } from "../keys.js";
import { issuerFromBaseUrl } from "../helpers.js";
import { renderUniversalLogin, SERVICE_LABEL } from "./ui.js";
import { recordLog } from "../events.js";

// Minimal-but-real SAML 2.0 IdP. /samlp/:clientId renders Universal Login and
// POSTs a genuinely RS256-signed <samlp:Response> to the client ACS. The
// signature is a real enveloped XML-DSig over the assertion so SDKs that verify
// it against the published certificate succeed. This is not a full SAML IdP
// (no encryption, single NameID format, simplified canonicalization).

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

// Compute an enveloped signature for an element with the given id. Returns the
// <ds:Signature> XML to insert into the element. Uses RSA-SHA256 + SHA-256
// digest. Canonicalization is simplified (the element is serialized as-is).
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
    `</ds:Reference>` +
    `</ds:SignedInfo>`;
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

export function samlRoutes({ app, store, baseUrl }: RouteContext): void {
  const as = getAuth0Store(store);
  const issuer = issuerFromBaseUrl(baseUrl);

  // SP-initiated SSO entry point: render Universal Login, carrying the SAML
  // relay state so the callback can build the response.
  app.get("/samlp/:clientId", (c) => {
    const clientId = c.req.param("clientId");
    const relayState = c.req.query("RelayState") ?? "";
    const client = as.clients.findOneBy("client_id", clientId);
    const acs = client?.callbacks[0] ?? "";
    return c.html(
      renderUniversalLogin(
        as.users.all(),
        client?.name ?? "SAML App",
        {
          redirect_uri: acs,
          state: relayState,
          client_id: clientId,
        },
        `/samlp/${clientId}/callback`,
      ),
    );
  });

  // SAML callback: build + sign the assertion and auto-POST it to the ACS.
  app.post("/samlp/:clientId/callback", async (c) => {
    const clientId = c.req.param("clientId");
    const body = await c.req.parseBody();
    const userRef = typeof body.user_ref === "string" ? body.user_ref : "";
    const acs = typeof body.redirect_uri === "string" ? body.redirect_uri : "";
    const relayState = typeof body.state === "string" ? body.state : "";
    const user = as.users.findOneBy("user_id", userRef);
    if (!user || !acs) return c.text("Invalid SAML login", 400);

    const xml = await buildSamlResponse({ issuer, acs, audience: clientId, user });
    await recordLog(store, { type: "ssa", description: "SAML SSO", clientId, userId: user.user_id });
    return c.html(
      renderFormPostPage(
        acs,
        { SAMLResponse: Buffer.from(xml).toString("base64"), RelayState: relayState },
        SERVICE_LABEL,
      ),
    );
  });

  // IdP metadata referencing the live signing certificate.
  app.get("/samlp/metadata/:clientId", async (c) => {
    const { publicDerB64 } = await nodeKeys();
    const md =
      `<?xml version="1.0"?>` +
      `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${xmlEscape(issuer)}">` +
      `<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
      `<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
      `<X509Data><X509Certificate>${publicDerB64}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
      `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${xmlEscape(baseUrl)}/samlp/${xmlEscape(c.req.param("clientId"))}"></SingleSignOnService>` +
      `</IDPSSODescriptor></EntityDescriptor>`;
    return c.body(md, 200, { "Content-Type": "application/xml" });
  });
}

async function buildSamlResponse(args: {
  issuer: string;
  acs: string;
  audience: string;
  user: { user_id: string; email: string; name: string };
}): Promise<string> {
  const { issuer, acs, audience, user } = args;
  const { publicDerB64 } = await nodeKeys();
  const responseId = `_${randomUUID().replace(/-/g, "")}`;
  const assertionId = `_${randomUUID().replace(/-/g, "")}`;
  const now = new Date(Date.now()).toISOString();
  const notOnOrAfter = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  // Build the assertion, then its signature, then embed it (enveloped).
  const assertionBody =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${now}">` +
    `<saml:Issuer>${xmlEscape(issuer)}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${xmlEscape(user.email)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${xmlEscape(acs)}"></saml:SubjectConfirmationData>` +
    `</saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${now}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${xmlEscape(audience)}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${now}">` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    `<saml:AttributeStatement>` +
    `<saml:Attribute Name="email"><saml:AttributeValue>${xmlEscape(user.email)}</saml:AttributeValue></saml:Attribute>` +
    `<saml:Attribute Name="name"><saml:AttributeValue>${xmlEscape(user.name)}</saml:AttributeValue></saml:Attribute>` +
    `</saml:AttributeStatement>`;

  const signature = await buildSignature(`${assertionBody}</saml:Assertion>`, assertionId, publicDerB64);
  const assertion = `${assertionBody}${signature}</saml:Assertion>`;

  return (
    `<?xml version="1.0"?>` +
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${now}" Destination="${xmlEscape(acs)}">` +
    `<saml:Issuer>${xmlEscape(issuer)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>` +
    assertion +
    `</samlp:Response>`
  );
}
