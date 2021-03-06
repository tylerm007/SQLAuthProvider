// this small section is provided by the Espresso Logic server when running in the server.
// a small emulator is provided for testing locally.

out = java.lang.System.out;

var SysUtility = {

    authenticate : function authenticate(server,port,database,username,password,roleQuery) {
        var sqlAuthService = new com.espressologic.authentication.sql.SQLAuthProvider(server,port,database);
        var result = sqlAuthService.authenticate(username,password,roleQuery);
        return result;
    }
};

// 1. load the class
load("SQLSecurityProvider.js");

// 2. configuration needed for testing
var configSetup = {
   serverName  : 'localhost',
   serverPort  : '3306' ,
   databaseName: 'sample',
   roleQuery : 'SELECT ur.roleName FROM sample.user_role ur , sample.user u where ur.username = u.loginName and u.loginName = ',
   groupRoleQuery : 'select roleName from sample.role',
   keyLifetimeMinutes : 60
};

// 3.this is how the server creates the security object
var sqlClient = SQLSecurityProviderCreate();
sqlClient.configure(configSetup);

var payload = {
    username: "Tyler",
    password: "Password1"
};

out.println("------------- testing sql authenticate with good payload");
var result = sqlClient.authenticate(payload);
out.println(JSON.stringify(result, null, 2));
out.println("-------------");


out.println("------------- testing sql authenticate with bad payload");
badPayload = {
    username: "DavidBAD",
    password: "Password$1"
};

result = sqlClient.authenticate(badPayload);
out.println(JSON.stringify(result, null, 2));
out.println("-------------");


var payload = {
    username: "Tyler",
    password: "Password1"
};


out.println("------------- testing getAllGroups");
result = sqlClient.getAllGroups(payload);
out.println(JSON.stringify(result, null, 2));
out.println("-------------");

out.println("------------- testing getLoginInfo");

result = sqlClient.getLoginInfo(null);
out.println(JSON.stringify(result, null, 2));
out.println("First field is " + result.fields[0].name);
out.println("-------------");

out.println("------------- testing getConfigInfo");
result = sqlClient.getConfigInfo();
out.println(JSON.stringify(result, null, 2));
out.println("First config prop is " + result.fields[0].name);
out.println("-------------");
