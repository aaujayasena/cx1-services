import ballerina/http;
import ballerina/time;
import ballerina/io;
import ballerina/random;
import ballerina/regex;
import ballerina/lang.'decimal as decimal;
import ballerina/lang.'string as string;
import ballerina/lang.runtime;

//External Identity provider Configurations
configurable string EXTERNAL_IDP_SERVICE_API = "https://externalidpmockservice.free.beeceptor.com";
const string EXTERNAL_IDP_SERVICE_CREATE_USER_ENDPOINT = "/pole/Users/Local";
const string EXTERNAL_IDP_SERVICE_GET_USER_CLAIMS_ENDPOINT = "/pole/users/claims";

//Asgardeo Configurations
configurable string ASGARDEO_TOKEN =  "<token>"; 
const string ASGARDEO_HOST = "https://dev.api.asgardeo.io/t/cx1org";
const int RETRY_COUNT = 3;
const decimal WAIT_TIME = 0.5;

enum Status {
    PASS = "pass",
    FAIL = "fail"
}

service / on new http:Listener(9090) {

    resource isolated function post proxyCreateUserinAsgardeo(@http:Payload json jsonObj, http:Caller caller) returns error? {

        json primaryEmail = check jsonObj.email;

        string correlationID = check jsonObj.correlationID.ensureType(string);
        log(string:concat("Asgardeo user payload : before formatting ", jsonObj.toJsonString()), correlationID, "proxyCreateUserinAsgardeo");

        json updatedUser = {
            emails: [primaryEmail],
            userName: check jsonObj.userName,
            password: passwordGenerator(),
            name: check jsonObj.name
        };

        http:Response quickResponse = new;
        json|error responseJson = createUserInAsgardeo(updatedUser, correlationID);

        if (responseJson is error) {
            log("Error while creating user in Asgardeo : " + responseJson.toString(), correlationID, "proxyCreateUserinAsgardeo");
        } else {
            quickResponse.statusCode = http:STATUS_OK;
            quickResponse.setJsonPayload(responseJson);

            check caller->respond(quickResponse);
        }

    }

    resource isolated function post proxyGetExternalIDPClaims(@http:Payload json jsonObj, http:Caller caller) returns error? {

        json federatedGroups = check jsonObj.federated_groups;
        string federatedGroupsStr = federatedGroups.toString();
        string[] federated_groups = regex:split(federatedGroupsStr, ",");
        string flow = check jsonObj.flow is () ? "login" : "password";

        string correlationID = check jsonObj.correlationID.ensureType(string);
        log(string:concat("External IDP  claim payload before formatting : ", jsonObj.toJsonString()), correlationID, "proxyGetExternalIDPClaims");

        json updatedPayload = {
            "email": check jsonObj.email,
            "objectId": check jsonObj.objectId,
            "idp_ref": check jsonObj.idp_ref,
            "federated_groups": federated_groups
        };

        http:Response quickResponse = new;
        json|error responseJson;

        if (flow == "login") {
            responseJson = getExternalIDPClaims(updatedPayload, correlationID);
        } else {
            //responseJson = retrieveNorthStarClaimsForPasswordGrant(updatedPayload, correlationID);
        }

        // if (responseJson is error) {
        //     log("Error while getting claims from External IDP claims API : " + responseJson.toString(), correlationID, "proxyGetExternalIDPClaims");
        // } else {
        //     quickResponse.statusCode = http:STATUS_OK; 
        //     quickResponse.setJsonPayload(responseJson);
        //     check caller->respond(quickResponse);
        // }

    }
}

//Pretty prints with function + correlation ID
isolated function log(string message, string correlationId, string functionName) {

    io:println("[" + functionName + "]" + "[" + correlationId + "] " + message);
}

//Creates a random password with letters, numbers, and symbols
isolated function passwordGenerator() returns string {

    string letters = "abcdefghijklmnopqrstuvwxyz";
    string numeric = "0123456789";
    string punctuation = "!@#$%^&*";
    string password = "";
    string character = "";

    decimal entity1 = decimal:ceiling(<decimal>letters.length() * <decimal>random:createDecimal());
    decimal entity2 = decimal:ceiling(<decimal>numeric.length() * <decimal>random:createDecimal());
    decimal entity3 = decimal:ceiling(<decimal>punctuation.length() * <decimal>random:createDecimal());
    string hold = letters.substring(<int>entity1 - 1, <int>entity1);
    character += hold;
    character += numeric.substring(<int>entity2 - 1, <int>entity2);
    character += punctuation.substring(<int>entity3 - 1, <int>entity3);
    entity1 = decimal:ceiling(<decimal>letters.length() * <decimal>random:createDecimal());
    entity2 = decimal:ceiling(<decimal>numeric.length() * <decimal>random:createDecimal());
    entity3 = decimal:ceiling(<decimal>punctuation.length() * <decimal>random:createDecimal());
    hold = letters.substring(<int>entity1 - 1, <int>entity1);
    hold = hold.toUpperAscii();
    character += hold;
    character += numeric.substring(<int>entity2 - 1, <int>entity2);
    character += punctuation.substring(<int>entity3 - 1, <int>entity3);
    entity1 = decimal:ceiling(<decimal>letters.length() * <decimal>random:createDecimal());
    entity2 = decimal:ceiling(<decimal>numeric.length() * <decimal>random:createDecimal());
    entity3 = decimal:ceiling(<decimal>punctuation.length() * <decimal>random:createDecimal());
    hold = letters.substring(<int>entity1 - 1, <int>entity1);
    character += hold;
    character += numeric.substring(<int>entity2 - 1, <int>entity2);
    character += punctuation.substring(<int>entity3 - 1, <int>entity3);
    entity1 = decimal:ceiling(<decimal>letters.length() * <decimal>random:createDecimal());
    hold = letters.substring(<int>entity1 - 1, <int>entity1);
    hold = hold.toUpperAscii();
    character += hold;
    password = character;

    return password.substring(0, 10);
};

isolated function createUserInAsgardeo(json jsonObj, string correlationID) returns @http:Cache json|error? {

    final string userName = check jsonObj.userName;
        final json & readonly userobj = <readonly>jsonObj;

    worker w1 returns json|error? {

        log("inside the worker - Asgardeo user creation", correlationID, "createUserInAsgardeo");

        boolean retryFlow = true;
        int currentRetryCount = 0;

        while (retryFlow && currentRetryCount < RETRY_COUNT) {
            http:ClientConfiguration httpClientConfig = {
                httpVersion: "1.1",
                timeout: 20
            };

            log("Before sending Asgardeo user get request", correlationID, "createUserInAsgardeo");
            http:Client|http:ClientError httpClient = new (ASGARDEO_HOST, httpClientConfig);
            if (httpClient is error) {
                log("Error while connecting to Asgardeo : " + httpClient.toString(), correlationID, "createUserInAsgardeo");
            } else {
                http:Response|http:ClientError getResponse = httpClient->get("/scim2/Users?filter=userName+eq+" + userName + "&attributes=id", {"Authorization": "Bearer " + ASGARDEO_TOKEN});
                if (getResponse is error) {
                    log("Error while getting the user information from Asgardeo : " + getResponse.toString(), correlationID, "createUserInAsgardeo");
                } else {
                    log("After getting the Asgardeo user get response", correlationID, "createUserInAsgardeo");

                    json|error getRespPayload = getResponse.getJsonPayload();
                    if (getRespPayload is error) {
                        log("Error while extracting the json response : " + getRespPayload.toString(), correlationID, "createUserInAsgardeo");
                    } else {
                        log(string:concat("Asgardeo get user response : ", getRespPayload.toJsonString()), correlationID, "createUserInAsgardeo");

                        int totalResults = check getRespPayload.totalResults;
                        log(string:concat("total user results", totalResults.toString()), correlationID, "createUserInAsgardeo");

                        if (totalResults == 1) {
                            log("total results 1", correlationID, "createUserInAsgardeo");
                            json[] resources = check getRespPayload.Resources.ensureType();
                            json userIdJson = resources[0];

                            log("inside the worker - Asgardeo get request - Before adding to the cache", correlationID, "createUserInAsgardeo");
                        //   //  string|error setCacheResponse = conn->pSetEx("au_".concat(userName), userIdJson.toJsonString(), 86400000);
                        //     if (setCacheResponse is error) {
                        //         log("Error while inserting the entry to Redis cache - Asgardeo Get Response : " + setCacheResponse.toString(), correlationID, "createUserInAsgardeo");
                        //     } else {
                        //         retryFlow = false;
                        //         log("inside the worker - Asgardeo get request - After adding to the cache", correlationID, "createUserInAsgardeo");
                        //     }

                        } else {
                            log("total results is not one . user is not available in Asgardeo", correlationID, "createUserInAsgardeo");
                            time:Utc beforeInvoke = time:utcNow();

                            http:Response postResponse = check httpClient->post("/scim2/Users?attributes=id", userobj, {"Authorization": "Bearer " + ASGARDEO_TOKEN});

                            time:Utc afterInvoke = time:utcNow();
                            time:Seconds respondTime = time:utcDiffSeconds(beforeInvoke, afterInvoke);
                            log(string:concat("Asgardeo User Creation latency : ", respondTime.toString()), correlationID, "createUserInAsgardeo");
                              int postResponseStatusCode  = postResponse.statusCode;
                            log("total results is not one . user is not available in Asgardeo" + postResponseStatusCode.toBalString(), correlationID, "createUserInAsgardeo" );
                          
                            
                            if(postResponseStatusCode == 409){
                                log("Possible concurrent request situation. Hence skipping the cache update!", correlationID, "createUserInAsgardeo");
                            } else {
                             log("total results is not one . user is not available in Asgardeo1111111111" , correlationID, "createUserInAsgardeo" );
                                json respPayload = check postResponse.getJsonPayload();
                                log("Response payload: " + respPayload.toJsonString(), correlationID, "functionName");
                                log(string:concat("Asgardeo user creation response : ", respPayload.toJsonString()), correlationID, "createUserInAsgardeo");

                                log("Before adding to the cache - Asgardeo user creation", correlationID, "createUserInAsgardeo");
                               // string|error setCacheResponse = check conn->pSetEx("au_".concat(userName), respPayload.toJsonString(), 86400000);

                                // if (setCacheResponse is error) {
                               
                                //     log("Error while inserting the entry to Redis cache - Asgardeo Post Response : " + setCacheResponse.toString(), correlationID, "createUserInAsgardeo");
                                // } else {
                                //     retryFlow = false;
                             
                                //     log("After adding to the cache - Asgardeo user creation", correlationID, "createUserInAsgardeo");
                                // }
                            }
                        }

                    }

                }
            }
            runtime:sleep(WAIT_TIME);
            currentRetryCount += 1;
        }

    }
    log("Sending accepted response for proxyCreateUserInAsgardeo endpoint.", correlationID, "createUserInAsgardeo");
    return {"status": "Accepted. Asgardeo user being created"};     
}

isolated function getExternalIDPClaims(json jsonObj, string correlationID) returns @http:Cache json|error? {

    log(string:concat("External IDP service claim payload : After formatting ", jsonObj.toJsonString()), correlationID, "getExternalIDPClaims");
    
    final string userid = check jsonObj.objectId;
    final json & readonly payload = <readonly>jsonObj;

    worker w1 returns json|error? {

        log("inside worker get northstar claims", correlationID, "getNorthStarClaims");

        boolean retryFlow = true;
        int currentRetryCount = 0;

        while (retryFlow && currentRetryCount < RETRY_COUNT) {
            http:ClientConfiguration httpClientConfig = {
                httpVersion: "1.1",
                timeout: 20
            };

            time:Utc beforeInvoke = time:utcNow();

            http:Client|http:ClientError httpEndpoint = new (EXTERNAL_IDP_SERVICE_API, httpClientConfig);
            if (httpEndpoint is error) {
                log("Error while connecting to NorthStar API : " + httpEndpoint.toString(), correlationID, "getNorthStarClaims");
            } else {
                http:Response|http:ClientError postResponse = httpEndpoint->post(EXTERNAL_IDP_SERVICE_CREATE_USER_ENDPOINT, payload, {"x-api-key": EXTERNAL_IDP_SERVICE_API});
                if (postResponse is error) {
                    log("Error while getting claims from NorthStarClaims endpoint : " + postResponse.toString(), correlationID, "getNorthStarClaims");
                } else {
                    json|error respPayload = postResponse.getJsonPayload();
                    if (respPayload is error) {
                        log("Error while extracting the json response payload -  NorthStarClaims : " + respPayload.toString(), correlationID, "getNorthStarClaims");
                    } else {
                        log(string:concat("Northstar claim response : ", respPayload.toJsonString()), correlationID, "getNorthStarClaims");

                        string organizationGUID = check respPayload.organization_GUID is () ? "EMPTY" : check respPayload.organization_GUID;
                        string entitlements = check respPayload.entitlements is () ? "EMPTY" : check respPayload.entitlements;
                        string groups = check respPayload.groups is () ? "EMPTY" : check respPayload.groups;
                        string organization = check respPayload.organization is () ? "EMPTY" : check respPayload.organization;
                        string sub_organization = check respPayload.sub_organization is () ? "EMPTY" : check respPayload.sub_organization;
                        string userID = check respPayload.userId is () ? "EMPTY" : check respPayload.userId;
                        userID = "" + userID;

                        if ((organizationGUID == "EMPTY") || (entitlements == "EMPTY") || (groups == "EMPTY") || (organization == "EMPTY") || (sub_organization == "EMPTY")) {
                            log("claims API response doesn't have claim values : ", correlationID, "getNorthStarClaims");
                            log("setting the cache value as nc2_error_".concat(userid), correlationID, "getNorthStarClaims");

                            //string|error insertCacheResponse = conn->pSetEx("nc2_error_".concat(userid), respPayload.toJsonString(), 9000000);

                            // if (insertCacheResponse is error) {
                            //     log("Error while inserting the error payload entry to Redis cache  - NorthStarClaims : " + insertCacheResponse.toString(), correlationID, "getNorthStarClaims");
                            // } else {
                            //     retryFlow = false;
                            //     log("After adding to the cache - Northstar claims", correlationID, "getNorthStarClaims");
                            // }
                        } else {
                            time:Utc afterInvoke = time:utcNow();
                            time:Seconds respondTime = time:utcDiffSeconds(beforeInvoke, afterInvoke);
                            log(string:concat("claims API latency : ", respondTime.toString()), correlationID, "getNorthStarClaims");
                            json updatedResponse = ();
                            // Processing the response before adding to the cache
                            // If the response contains the status key, then it is an error response
                            if (!respPayload.toString().includes("\"status\"")) {
                                json groupsFromResponse = check respPayload.groups;
                                json rolesFromResponse = check respPayload.roles;

                                string groupsstr = groupsFromResponse.toString();
                                if (groupsstr.length() > 0) {
                                    if groupsstr.length() > 2 {
                                        groupsstr = groupsstr.substring(2, groupsstr.length() - 2);
                                    } else {
                                        groupsstr = groupsstr.substring(1, groupsstr.length() - 1);
                                    }

                                    groupsstr = regex:replaceAll(groupsstr, "\",\"", ";,;,;");
                                } else {
                                    groupsstr = "";
                                }

                                string rolesstr = rolesFromResponse.toString();

                                if (rolesstr.length() > 0) {
                                    if rolesstr.length() > 2 {
                                        rolesstr = rolesstr.substring(2, rolesstr.length() - 2);
                                    } else {
                                        rolesstr = rolesstr.substring(1, rolesstr.length() - 1);
                                    }

                                    rolesstr = regex:replaceAll(rolesstr, "\",\"", ";,;,;");
                                    rolesstr = regex:replaceAll(string:concat(";,;,;", rolesstr), ",\"", "\";,;,;");
                                } else {
                                    rolesstr = "";
                                }

                                string? groups_roles = "";
                                if (groupsstr.length() > 0 || rolesstr.length() > 0) {
                                    groups_roles = string:concat(groupsstr, rolesstr);
                                } else {
                                    groups_roles = ();
                                }

                                json subOrg = ();

                                if respPayload.toString().includes("\"sub_organization\":") {
                                    subOrg = check respPayload.sub_organization;
                                }

                                updatedResponse = {
                                    "userId": <int>(check respPayload.userId),
                                    "groups": groups_roles,
                                    "entitlements": check respPayload.entitlements,
                                    "organization": check respPayload.organization,
                                    "organization_GUID": check respPayload.organization_GUID,
                                    "sub_organization": subOrg
                                };

                                log("Updated response for the getNorthStarClaims  : " + updatedResponse.toString(), correlationID, "getNorthStarClaims");
                            } else {
                                log("Error response from the NorthStarClaims API : " + respPayload.toString(), correlationID, "getNorthStarClaims");
                                updatedResponse = respPayload;
                            }

                            log("Before adding to the cache - Northstar claims", correlationID, "getNorthStarClaims");
                            // string|error insertCacheResponse = conn->pSetEx("nc2_".concat(userid), updatedResponse.toJsonString(), 9000000);
                            // if (insertCacheResponse is error) {
                            //     log("Error while inserting an entry to Redis cache  - NorthStarClaims : " + insertCacheResponse.toString(), correlationID, "getNorthStarClaims");
                            // } else {
                            //     retryFlow = false;
                            //     log("After adding to the cache - Northstar claims", correlationID, "getNorthStarClaims");
                            // }
                        }

                    }

                }

            }
            runtime:sleep(WAIT_TIME);
            currentRetryCount += 1;

        }

    }
    log("Sending accepted response for proxyNorthstarClaims endpoint.", correlationID, "getNorthStarClaims");
    return {"status": "Accepted. Claims being retrieved from Northstar"};
}

