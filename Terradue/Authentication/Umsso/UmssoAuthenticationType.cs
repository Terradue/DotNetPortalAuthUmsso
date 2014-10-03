﻿using System;
using Terradue.Portal;
using System.Web;
using System.IO;
using System.Xml;
using System.Text.RegularExpressions;

namespace Terradue.Umsso {
    public class UmssoAuthenticationType : AuthenticationType {

        /// <summary>
        /// Indicates whether the authentication type depends on external identity providers.
        /// </summary>
        /// <value><c>true</c> if uses external identity provider; otherwise, <c>false</c>.</value>
        public override bool UsesExternalIdentityProvider {
            get {
                return true;
            }
        }

        /// <summary>
        /// In a derived class, checks whether an session corresponding to the current web server session exists on the
        /// external identity provider.
        /// </summary>
        /// <returns><c>true</c> if this instance is external session active the specified context request; otherwise, <c>false</c>.</returns>
        /// <param name="context">Context.</param>
        /// <param name="request">Request.</param>
        public override bool IsExternalSessionActive(IfyWebContext context, HttpRequest request){
            return true;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Terradue.OpenId.AuthenticationOpenId"/> class.
        /// </summary>
        public UmssoAuthenticationType(IfyContext context) : base(context) {}

        /// <summary>
        /// Gets the user profile.
        /// </summary>
        /// <returns>The user profile.</returns>
        /// <param name="context">Context.</param>
        /// <param name="request">Request.</param>
        public override User GetUserProfile(IfyWebContext context, HttpRequest request, bool strict){
            string ConfigurationFile = context.SiteConfigFolder + Path.DirectorySeparatorChar + "auth.xml";
            XmlDocument authDoc = new XmlDocument();

            try {
                authDoc.Load(ConfigurationFile);
                foreach (XmlNode typeNode in authDoc.SelectNodes("/externalAuthentication/method[@active='true']/accountType")) {
                    XmlElement methodElem = typeNode.ParentNode as XmlElement;
                    XmlElement typeElem = typeNode as XmlElement;
                    if (typeElem == null || methodElem == null) continue;

                    // The received "Host" header must match exactly the value of the "host" attribute.
                    if (methodElem.HasAttribute("host") && methodElem.Attributes["host"].Value != HttpContext.Current.Request.Headers["Host"]) continue;

                    // The request origin ("REMOTE_HOST" server variable) must have (or be) the same IP address as the hostname (or IP address) in the value of the "remoteHost" attribute.
                    if (methodElem.HasAttribute("remoteHost") && !context.IsRequestFromHost(methodElem.Attributes["remoteHost"].Value)) continue;

                    bool match = true;
                    foreach (XmlNode conditionNode in typeElem.SelectNodes("condition")) {
                        XmlElement conditionElem = conditionNode as XmlElement;
                        if (conditionElem == null) continue;

                        string value = null, pattern = null;
                        if (conditionElem.HasAttribute("header")) value = HttpContext.Current.Request.Headers[conditionElem.Attributes["header"].Value];
                        else continue;

                        if (conditionElem.HasAttribute("pattern")) pattern = conditionElem.Attributes["pattern"].Value;
                        else continue;

                        if (value == null || pattern == null) continue;

                        if (!Regex.Match(value, pattern).Success) {
                            match = false;
                            break;
                        }
                    }
                    if (!match) continue;

                    XmlElement loginElem = typeElem["login"];
                    if (loginElem == null) continue;

//                    /* WARNING - Change (Enguerran) - we now use the email as identifier, not the username anymore */
//                    XmlElement mailElem = loginElem["email"];
//                    if (mailElem == null) continue;

                    // Get username from <login> element
                    string externalUsername = null;
                    if (loginElem.HasAttribute("header")) externalUsername = HttpContext.Current.Request.Headers[loginElem.Attributes["header"].Value];

                    if (externalUsername == null) continue;
                    //context.IsUserIdentified = true;

                    EntityType userEntityType = EntityType.GetEntityType(typeof(User));
                    AuthenticationType authType = IfyWebContext.GetAuthenticationType(typeof(UmssoAuthenticationType));

                    bool exists = User.DoesUserExist(context, externalUsername, authType);
                    User user = User.GetOrCreate(context, externalUsername, authType);

                    bool register = !exists && loginElem.HasAttribute("register") && loginElem.Attributes["register"].Value == "true";
                    bool refresh = exists && loginElem.HasAttribute("refresh") && loginElem.Attributes["refresh"].Value == "true";


                    // If username was not found and automatic registration is configured, create new user
                    // If username was found return with success
                    if (register || refresh) {
                        if (register) {
                            user.AccountStatus = AccountStatusType.Enabled;
                        } else {
//                            context.IsUserAuthenticated = true; // TODO: REMOVE
                        }

                        foreach (XmlElement elem in loginElem.ChildNodes) {
                            if (elem == null) continue;
                            string value = null;
                            if (elem.HasAttribute("header")) value = HttpContext.Current.Request.Headers[elem.Attributes["header"].Value];

                            switch (elem.Name) {
                                case "firstName" :
                                    user.FirstName = value;
                                    break;
                                case "lastName" :
                                    user.LastName = value;
                                    break;
                                case "email" :
                                    user.Email = value;
                                    break;
                                case "affiliation" :
                                    user.Affiliation = value;
                                    break;
                                case "credits" :
                                    int credits;
                                    Int32.TryParse(value, out credits);
                                    user.TotalCredits = credits;
                                    break;
                                case "proxyUsername" :
                                    //user.ProxyUsername = value;
                                    break;
                                case "proxyPassword" :
                                    //user.ProxyPassword = value;
                                    break;
                            }
                        }
                    }
                    return user;
                }
                return null;

            } catch (Exception e) {
                throw new Exception("Invalid authentication settings" + " " + e.Message + " " + e.StackTrace);
            }
        }

        /// <summary>
        /// Ends the external session.
        /// </summary>
        /// <param name="context">Context.</param>
        /// <param name="request">Request.</param>
        /// <param name="response">Response.</param>
        public override void EndExternalSession(IfyWebContext context, HttpRequest request, HttpResponse response) {
            response.Redirect(context.HostUrl.Replace("http://", "https://") + "/Shibboleth.sso/Logout");
        }
    }
}

