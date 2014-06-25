//Upload this JavaScript to EspressoLogic Stormpath Authentication Provider
function SQLSecurityProviderCreate() {

    var result = {};
    var configSetup = {
  		serverName  : '',
   		serverPort  : '' ,
   		databaseName: '',
   		roleQuery: '',
   		groupRoleQuery : '',
        keyLifetimeMinutes : 60
    };

    //FUNCTION this call must be made first to pass in the required SQL configuration values
    result.configure = function configure(myConfig) {
		configSetup.serverName 	= myConfig.serverName || '';
   		configSetup.serverPort  = myConfig.serverPort || '' ;
   		configSetup.databaseName = myConfig.databaseName || '';
   		configSetup.roleQuery = myConfig.roleQuery || '';
   		configSetup.groupRoleQuery = myConfig.groupRoleQuery || '';
        configSetup.keyLifetimeMinutes = myConfig.keyLifetimeMinutes || 60;
    };

    //NOTE: the function configure must be called first - this will validate the sql user account
    //FUNCTION AUTHENTICATE REQUIRES PAYLOAD {username : '', password : ''}
    result.authenticate = function authenticate(payload) {

        //helper function to return an named value pairs of customData (exlude reserved fields)
        var parseCustomData =  function parseCustomData(result, stringHREF) {
            for (var id in stringHREF) {
                if (!stringHREF.hasOwnProperty(id)) {
                    continue;
                }
                if (RESERVED_FIELDS_HREF.indexOf(id) != -1) {
                    continue;
                }
                if (stringHREF.hasOwnProperty('customData')) {
                    var customdata = stringHREF[id];
                    for (var key in customdata) {
                        result[key] = customdata[key];
                    }
                }
            }
        };

        var roles = [];
        var errorMsg = null;
        var resetPasswordURL = null;
        var forgotPasswordURL = null;
        var customDataHREF = {};

		var roleQuery = configSetup.roleQuery +"'" + payload.username + "'";
        try {
            //POST this JSON request to determine if username and password account is valid
            var loginAttempt = SysUtility.authenticate(configSetup.serverName,configSetup.serverPort,configSetup.databaseName,payload.username,payload.password,roleQuery);

            var groups = JSON.parse(loginAttempt);
            if (groups.hasOwnProperty('errorMessage')) {
					errorMsg = groups.errorMessage;
			} else {
				//note: change field name below to match column with role name
				for (var row in groups) {
					roles.push(groups[row].role);
				}

			}
        }
        catch (e) {
                errorMsg = e.message;
        }

        var autResponse = {
            errorMessage: errorMsg,
            roleNames: roles,
            userIdentifier: payload.username,
            keyExpiration: new Date(+new Date() + (+configSetup.keyLifetimeMinutes) * 60 * 1000),
            resetPasswordURL: resetPasswordURL,
            forgotPasswordURL: forgotPasswordURL,
            userData: customDataHREF,
            lastLogin : {
                datetime: null,
                ipAddress : null
            }
        };
        return autResponse;
    };

    //FUNCTION getAllGroups is used to map all available groups for existing application - DO NOT CHANGE
    result.getAllGroups = function getAllGroups(payload) {
        var roles = [];
        var errorMsg = null;

        try {
			//we could easily use a REST call here and would pass the APIKey in with the payalod Sysutility.getJSON(url,settings,parameters);  see apiDoc
            var groupsResponse = SysUtility.authenticate(configSetup.serverName,configSetup.serverPort,configSetup.databaseName,payload.username,payload.password,configSetup.groupRoleQuery);
			var groups = JSON.parse(groupsResponse);
			if (groups.hasOwnProperty('errorMessage')) {
					errorMsg = groups.errorMessage;
			} else {
				//note: change field name below to match column with role name
				for (var row in groups) {
					roles.push(groups[row].role);
				}
			}
        } catch(e) {
            errorMsg = e.message;
        }

        var autResponse = {
            errorMessage: errorMsg,
            roleNames: roles
        };

        return autResponse;
    };
    //FUNCTION getLoginInfo is used to create the logon dialog - DO NOT CHANGE
    result.getLoginInfo = function getLoginInfo() {
        return {
            fields: [
                {
                    name: "username",
                    display: "Username",
                    description: "Enter your Username",
                    type: "text",
                    length: 40,
                    helpURL: "http://docs.stormpath.com/java/quickstart/#authenticate-an-account"
                },
                {
                    name: "password",
                    display: "Password",
                    description: "Enter your Password",
                    type: "password",
                    length: 40,
                    helpURL: "http://docs.stormpath.com/java/quickstart/#authenticate-an-account"
                }
            ],
            links : [
                {
                    display: "Forgot password?",
                    href: "https://api.stormpath.com/forgotLogin"
                },
                {
                    display: "Forgot Tenant?",
                    href: "https://api.stormpath.com/forgotTenant"
                }
            ]
        };
    };


	//this is called when you setup a new authentication provider in LogicDesigner to prompt for your fixed internal values
    result.getConfigInfo = function getConfigInfo() {
        return {
            current : {

                "keyLifetimeMinutes" : configSetup.keyLifetimeMinutes,
                "serverName" : configSetup.serverName,
                "databaseName" : configSetup.databaseName,
                "roleQuery" : configSetup.roleQuery,
                "groupRoleQuery" : configSetup.groupRoleQuery
            },
            fields : [
                {
                    name: "serverName",
                    display: "SQL Server Name (required)",
                    type: "text",
                    length: 40,
                    helpURL: ""
                },
                {
                    name: "Port",
                    display: "Port (required)",
                    type: "text",
                    length: 40,
                    helpURL: ""
                },
                 {
					name: "Database",
					display: "Database Name (required)",
					type: "text",
					length: 40,
					helpURL: ""
                },
                 {
					name: "roleQuery",
					display: "Sql Query used to valid username (must have logon access to Database) and return list of all roles (required)",
					type: "text",
					length: 40,
					helpURL: ""
                },
                 {
					name: "groupRoleQuery",
					display: "Sql Query used to return a list of all roles in system (optional)",
					type: "text",
					length: 40,
					helpURL: ""
                },
                {
                    name: "keyLifetimeMinutes",
                    display: "API Key Lifetime (Minutes)",
                    type: "number",
                    length: 8,
                    helpURL: "http://www.espressologic.com"
                }
            ],
            links: []
        };
    };

    return result;
}
