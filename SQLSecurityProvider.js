//Upload this JavaScript to EspressoLogic Stormpath Authentication Provider
function SQLSecurityProviderCreate() {

    var result = {};
    var configSetup = {
  		serverName  : '',
   		serverPort  : '' ,
   		databaseName: '',
        keyLifetimeMinutes : 60
    };

    //FUNCTION this call must be made first to pass in the required SQL configuration values
    result.configure = function configure(myConfig) {
		configSetup.serverName 	= myConfig.serverName || '';
   		configSetup.serverPort  = myConfig.serverPort || '' ;
   		configSetup.databaseName = myConfig.databaseName || '';
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

        try {
            //POST this JSON request to determine if username and password account is valid
            var loginAttempt = SysUtility.authenticate(configSetup.serverName,configSetup.serverPort,configSetup.databaseName,payload.username,payload.password,payload.roleQuery);

            var groups = JSON.parse(loginAttempt);
            if (groups.hasOwnProperty('role')) {
				for (var i = 0; i < groups.length; i++) {
					roles.push(groups[i].role);
					//var customdata = groups.items[i].customData;
					//parseCustomData(customDataHREF, customdata);
				}

		} else {
			errorMsg = loginAttempt;
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
    result.getAllGroups = function getAllGroups() {
        var roles = [];
        var errorMsg = null;

        try {
            var groupsResponse = SysUtility.authenticate(configSetup.serverName,configSetup.serverPort,configSetup.databaseName,payload.username,payload.password,payload.roleQuery);
            var groups = JSON.parse(groupsResponse);

            for (var i = 0; i < groups.length; i++) {
				roles.push(groups[i].role);
			}

        }
        catch(e) {
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

    result.getConfigInfo = function getConfigInfo() {
        return {
            current : {

                "keyLifetimeMinutes" : configSetup.keyLifetimeMinutes
            },
            fields : [
                {
                    name: "serverName",
                    display: "SQL Server Name",
                    type: "text",
                    length: 40,
                    helpURL: ""
                },
                {
                    name: "Port",
                    display: "Port",
                    type: "text",
                    length: 40,
                    helpURL: ""
                },
                 {
						name: "Database",
						display: "Database Name",
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
