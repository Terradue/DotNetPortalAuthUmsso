using System;
using System.Data;
using System.IO;
using System.Text.RegularExpressions;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Terradue.Portal;
using Terradue.Util;

/*!
\defgroup modules_umsso UM-SSO
@{
This module enables external authentication using UM-SSO mechanism. 
In the core, the \ref core_Context component provides with an interface
that allows using HTTP headers present in the HHTP context to authenticate the user.
Associated with a set of rules, the \ref core is able to establish a protocol to authenticate user.
\ref umrea "Code ruleset" is the excerpt of the ruleset configured in ngEO to enable UM-SSO authentication. 
The externalAuthentication is declared with the method UM-SSO. accountType maps the rule to an account. 
The rule is applied only if the condition that specified that the header \c Umsso-Person-commonName
is present and not empty. Then the value present in \c Umsso-Person-commonName is used as login username
and user is registered automatically if not yet present in the database with register="true" 
and the user receives a account creation mail with the mail information found in header Umsso-Person-Email.

\anchor umrea
\code{.xml}
<?xml version="1.0" encoding="UTF-8"?>
<externalAuthentication>
    <method name="UM-SSO" active="true">
        <!-- List of user groups expressed with regular expression -->
        <!-- Each pattern matching corresponds to a privilege -->
        <accountType>
            <condition header="Umsso-Person-commonName" pattern=".+" />
            <login header="Umsso-Person-commonName" register="true" mail="true">
                <email header="Umsso-Person-Email" />
            </login>
        </accountType>
    </method>
</externalAuthentication>
\endcode

\ingroup modules

\ref uasd depicts the scenarios that applies when a user perform an HTTP request to a web service protected by UM-SSO. This scenario is the “normal” case where user credentials are correct.

\anchor uasd
\image latex "graphics/sequence/umsso_authentication.eps" "UM-SSO authentication sequence diagram" width=10cm

\section sec_modules_umssoPurpose Purpose

| Requirements  | Abstract | Purpose |
| ------------- | -------- | ------- |
| \req{ngEO-SUB-005-WEBS-DES} | UM-SSO Authentication | User’s requests are authenticated by the Web server via UM-SSO. |
| \req{ngEO-SUB-006-WEBS-DES} | Authentication | The Web client is redirected to the UM-SSO for the first connection to the Web server and after a log-in/log-out action. |

\section sec_modules_umssoDependencies Dependencies

- \ref core_Context, via the IExternalAuthentication interface, it implements an authentication mechanism

\section sec_modules_umssoInterfaces Interfaces 

This component implements those interfaces

\icd{IExternalAuthentication}

\section sec_modules_umssoReferences References

- \refdoc{SIE-UMSSO-SP-INT-001}

@}

*/

namespace Terradue.Umsso {



    //-------------------------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------------------------------------------------



    public class UmssoUtils {
        
        /// <summary>Creates the instance on the cloud provider and stores the record in the local database.</summary>
        public static bool BindToUmssoIdp(IfyContext context, string idpUserAccount, string spUserAccount, string transactionId) {
            bool result = false;
            
            string url = context.GetConfigValue("UmssoIdpBindingUrl"); //"/home/umsso/sp/cert/portal-dev.gpod-sso.terradue.int.p12";
            //url = "http://portal-dev.gpod.terradue.int/analyze.aspx";
            string certFileName = context.GetConfigValue("UmssoSpCertFile"); //"/home/umsso/sp/cert/portal-dev.gpod-sso.terradue.int.p12";
            /*UmssoIdpServicesSOAP ws = new UmssoIdpServicesSOAP(url, certFileName);
            string result = ws.bind(idpUserAccount, spUserAccount, "b2cc8f0f-8fcf-479f-9153-93f7f6274596");
            context.AddInfo(result);*/
            try {
                HttpWebRequest request = GetSslRequest(url, "POST", "text/xml; charset=utf-8", certFileName);
                Stream requestStream = request.GetRequestStream();
                XmlTextWriter writer = new XmlTextWriter(requestStream, System.Text.Encoding.UTF8);
                
                writer.WriteStartDocument();
                writer.WriteStartElement("soap:Envelope");
                writer.WriteAttributeString("xmlns", "soap", null, "http://schemas.xmlsoap.org/soap/envelope/");
                //writer.WriteNamespaceDefinition("soap", "http://schemas.xmlsoap.org/soap/envelope/");
                writer.WriteAttributeString("soap:encodingStyle", "http://schemas.xmlsoap.org/soap/encoding/");
                writer.WriteStartElement("soap:Body");
                writer.WriteAttributeString("xmlns", "m", null, "http://interfaces.soap.umsso20.sde.siemens.com");
                //writer.WriteNamespaceDefinition("m", "http://interfaces.soap.umsso20.sde.siemens.com");
                writer.WriteStartElement("m:bind");
                writer.WriteElementString("m:args0", idpUserAccount);
                writer.WriteElementString("m:args1", spUserAccount);
                writer.WriteElementString("m:args2", transactionId);
                writer.WriteEndElement(); // </m:bind>
                writer.WriteEndElement(); // </soap:Body>
                writer.WriteEndElement(); // </soap:Envelope>
                writer.Close();
                requestStream.Close();

                // Get response stream.
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                XmlDocument doc = new XmlDocument();
                doc.Load(response.GetResponseStream());
                response.Close();

                XmlNamespaceManager nsm = new XmlNamespaceManager(doc.NameTable);
                nsm.AddNamespace("soapenv", "http://schemas.xmlsoap.org/soap/envelope/");
                nsm.AddNamespace("ns1", "http://interfaces.soap.umsso20.sde.siemens.com");
                nsm.AddNamespace("bind", "bind.xmlbeans.configuration.umsso20.sde.siemens.com");
                XmlElement responseElem = doc.SelectSingleNode("soapenv:Envelope/soapenv:Body/ns1:bindResponse/ns1:return", nsm) as XmlElement;
                if (responseElem == null) throw new Exception("Invalid response from binding service");
                doc.LoadXml(responseElem.InnerText); // encoded XML inside XML
                XmlElement codeElem = doc.SelectSingleNode("bind:bindServiceResponse/bind:code", nsm) as XmlElement;
                XmlElement messageElem = doc.SelectSingleNode("bind:bindServiceResponse/bind:message", nsm) as XmlElement;
                if (codeElem != null && codeElem.InnerText == "UMSSO_MSG_OK") result = true;
                else if (messageElem != null) throw new Exception(messageElem.InnerText);
                
                context.AddInfo(doc.OuterXml);

            } catch (Exception e) {
                context.ReturnError(e.Message);
                return false;
            }
            
            return result;
        }

        //---------------------------------------------------------------------------------------------------------------------

        public static HttpWebRequest GetSslRequest(string url, string method, string contentType, string certFileName) {
            HttpWebRequest request = null;
            request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;
            if (contentType != null) request.ContentType = contentType;
            
            request.ClientCertificates.Add(new X509Certificate2(certFileName, String.Empty, X509KeyStorageFlags.DefaultKeySet));

            ServicePointManager.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate, X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors) {
                return true;
            };
            
            return request;
        }
        
        
    }
    
}

