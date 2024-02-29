# BZFlag Central Services Design (bzfcs)

This will document, in detail, the current functionality of the current implementation (BZFlag List server a.k.a. bzfls), describe challenges with the current design, and define the requirements and functionality for a future version of bzfls.

## Current Design

The current design is mostly a single PHP file and tightly integrates with some internals of phpBB by directly including various phpBB files, including some rather large files for UTF-8 normalization. The code also accesses two separate databases: one for bzfls, and the phpBB database itself. There are a couple other files, such as a simple database class for reading/writing to the bzfls database, and another for handling IP, hostname, and user bans.

### Entry point

We start off by including a bunch of phpBB files and setting up that environment. We also connect to our database and get a list of active bans. We build up an array of addresses and hostnames to check, which at this point is just the ```$_SERVER['REMOTE_ADDR']``` and the hostname resolved from ```gethostbyaddr($_SERVER['REMOTE_ADDR'])```, if one is found. If we find a matching ban, the script will be terminated here. If the ban is silent, a simple 'exit' is called. Otherwise we print "ERROR: Connection attempt rejected.  See #bzflag on irc.freenode.net".

After the ban check, we set some cache headers to tell proxies not to cache, and then look at the action input parameter to decide which action to execute.

### String Validators

The current bzfls has string validator functions designed for most user input. They use short and rather cryptic names, such as ```vcsoe``` or ```vnpod```. The "v" just means "validate", and the "oe" or "od" means "or error" or "or die" respectively. The middle indicate what it is *typically* used to validate, such as "cs" being "callsign" or "h" being "hexadecimal".

However, due to a coding error regarding equality checking, *nothing was ever flagged as invalid*.  So we're going to disregard all of that.  Additionally, the ```vctod``` function had another coding error in that the valid characters were surrounded by single quotes instead of double quotes, so the line break and carriage return characters wouldn't have been allowed as intended.

### HTML interface

There is a basic HTML interface that was mostly for testing.  It simply has fields for all of the possible inputs.  This is rather uninteresting and won't be covered in this document.

### Utility functions

There are a few utility functions where the same code would be needed for multiple actions.

#### ```authenticate_player```

This function accepts a username and password, and then defines a ```$clean_callsign``` variable using phpBB's utf8_clean_string function. A query is run to select the username, user_id and user_password columns from the phpBB users table where the username_clean column matches the value of ```$clean_callsign``` and the user_inactive_reason is 0 (which indicates that the user is active).

If we're able to fetch the information from the database and the ```phpbb_check_password``` function returns true (indicating the password is correct), then we generate and store an authentication token. The token is generated using ```base64_encode(random_bytes(14))```. The ```authenticate_player``` function then returns the player player information (username and user_id). If the player doesn't exist or the password was incorrect, the function returns false.

#### ```checktoken```

This function accepts a callsign, HTTP request IP address, token, and array of group names.

It prints out "MSG checktoken callsign=CALLSIGN, ip=IP, token=TOKEN group=GROUP1 group=GROUP2", with CALLSIGN, IP, and TOKEN being the passed in callsign, IP address, and token respectively. The array of groups is written out with a group=GROUPNAME for each. Note that there is a comma after the callsign and IP, but nowhere else in the line.

Stale time is calculated as time() - 300 seconds (which is 5 minutes).

The callsign is cleaned the same way as authenticate_player, and and then a check is made to verify that the user exists. If it doesn't exist, "UNK: CALLSIGN" is printed, where CALLSIGN is the passed in player callsign. Then the function returns.

If the user does exist, the clean callsign, token, IP, and stale time are passed to a database call to fetch the user_id from the phpBB users database, where the clean callsign and token match what is provided, the IP address, if provided, matches, and the token timestamp is greater than the stale time.

If a valid token is found, the user_id is fetched, the user_lastvisit date is updated and the token date is set to 0, indicating that it has been used. We print "TOKGOOD: CALLSIGN", where CALLSIGN is the player's callsign. If groups were passed in, we check if the player is a member of any of them and append a colon delimited list of those groups, with a colon also joining the callsign and the first group name. (Example: TOKGOOD: CallsignHere:Group1:Group2:Group5) Then on a new line, we print "BZID: ID CALLSIGN", where ID is the user_id and CALLSIGN is the callsign.

If a valid token is not found, we print "TOKBAD: CALLSIGN", where CALLSIGN is the player's callsign.

### Actions

The action input parameter decides what code path will be followed. Each action is typical broken down into a separate function in the bzfls code, though some actions, like the LIST action, might call the function of a second action.

#### LIST action

The LIST action uses the following input parameters: callsign, password, version, listformat, local

The first thing the list action does is delete any servers that haven't sent in an ADD action in 1830 seconds (30.5 minutes). Game servers send an ADD action every time a player joins or leaves, and at least every 15 minutes. The 30.5 minute cutoff allows a missed ADD on an empty server.

If any stale servers were purged, the advertisement groups (used to show a server to only certain player groups) are cleaned up, removing any where the server no longer exists.

If the callsign and password parameters are provided, they are passed to the ```authenticate_player``` function. If this returns false, an empty token is set (indicating an authentication failure) and servers that are advertised to everyone and have the same protocol version (if provided) are fetched.

If the ```authenticate_player``` function returns the player data, servers are fetched based on what the user should see based on the advertisement groups. **There is some extra magic around the VERIFIED group in the database query, so check into that as well.** Additionally, a check for any unread private messages and made. If any exist, a NOTICE is printed indicating how many. This would show up in the game client on the message console.

If the callsign or password isn't provided, then just the servers that are advertised to everyone are fetched, and no token is defined.

There are three output formats: normal, lua, and json. The normal mode is the default when lua and json isn't specified. The lua format was targeted for use in BZFlag 2.99's lua support. The json format is a bastardized CSV export, where there's just an object with three members (token, fields, and servers). The token field is set if the token is defined and not empty. The fields member has the names of the data columns and the servers member just has an array of the server information.  *AUTHORS NOTE: Both of these list formats should die in a fire.*

The normal output format checks if the token is set. If it is set, but empty, it prints out a "NOTOK: invalid callsign or password" line. If it is set and not empty, it prints out "TOKEN: " followed by the token. Then for each server passed in to the function, it writes out, separated by a space, the nameport, protocol version, gameinfo hex, server IP address, and public description (title).

#### ADD action

The ADD action uses the following input parameters: nameport, version, gameinfo, title, checktokens, groups, serverKey, advertgroups

If the protocol version is not for BZFlag 2.0 or 1.10, or there's a server key provided, an attempt is made to fetch information about the provided server key. If the key is not found, we print "ERROR: Missing or invalid server authentication key" and terminate further processing of the action. We then look at the host value from the server key database and resolve that back to an IP with gethostbyname and compare that IP to the ```$_SERVER['REMOTE_ADDR']``` value. If it does not match, we print "ERROR: Host mismatch for server authentication key" and terminate further processing of the action. Then we attempt to look up the owner by BZID. If that fails, we print "ERROR: Owner lookup failure" and terminate further processing of the action. If everything worked, we store a copy of the owner BZID for further use.

We then print out "MSG: ADD NAMEPORT VERSION GAMEINFO TITLE", where NAMEPORT, VERSION, GAMEINFO, and TITLE are the provided nameport, protocol version, gameinfo hex, and title as provided by the game server.

A regular expression is used to verify that the protocol version matches the format ```[A-Z]{4}[0-9]{4}```. If that does not match, we terminate further processing of the action.

The nameport value is split on the colon into two separate variables, with the port defaulting to 5154 if it isn't specified.

The hostname is resolved to an array of IPv4 addresses using ```gethostbynamel```, and then checked to make sure it isn't ```=== FALSE``` and the size of the array is 1 (indicating that the host resolves to exactly 1 IPv4 address). If either of those fail, we print "ERROR: Provided hostname does not resolve to a single IPv4 address" and terminate further processing of the action.

The resolved IP address of the provided hostname (or the raw IP if no hostname was provided) is compared against ```$_SERVER['REMOTE_ADDR']```. If they do not match, we print "ERROR: Requesting address is REMOTE_ADDR while server is at SERVIP", where REMOTE_ADDR is ```$_SERVER['REMOTE_ADDR']``` and SERVIP is the resolved IP of the provided hostname or the bare IP provided. And then the script is terminated with the die() function, unlike previous cases where just the action function was terminated with return.

Next we try to open a socket to the server hostname and port, with a 5 second timeout specified. If we are unable to connect, we print "ERROR: Unable to reach your server. Check your router/firewall and DNS configuration." and terminate further processing of the action.

We then check if a server with the same nameport exists already. If it does, we print "MSG: updating NAMEPORT", where NAMEPORT is the nameport. Then we update the database record by passing in the found server ID, the server key's ownerID and owner name, and the provided nameport, gameinfo, title, protocol version, and build.

If a server with the specified nameport doesn't exist, we create a new record using the server key's ownerID and owner name, and the provided nameport, gameinfo, title, protocol version, and build. If the server is added correctly, we then define the advertisement groups for the server. We explode the comma separated list provided by the advertgroups input argument. If the avertgroups input argument isn't set or the list of groups contains EVERYONE, we add an advertgroup for this server ID with the group ID of 0. Otherwise, for each group in the list, fetch the group ID using the group name, and add that group to the advertgroup table.

If there is an owner name, which should be the case for any server with a valid server key, we print "OWNER: NAME" where NAME is the owner name.

At this point, we call the function for the CHECKTOKENS action.

Finally, we print "ADD NAMEPORT" where NAMEPORT is the provided nameport input parameter.

#### REMOVE action

The REMOVE action uses the following input parameter: nameport

We print "MSG: REMOVE request from NAMEPORT" where NAMEPORT is the provided nameport input parameter. Then we split the nameport on the colon into two variables, name and port, with port defaulting to 5154 if it isn't provided.

The server name is resolved to a list of IPv4 addresses. Like in the ADD action, if the number of addresses isn't exactly 1, we print "ERROR: Provided hostname does not resolve to a single IPv4 address" and terminate further processing of the action.

Otherwise, we compare the ```$_SERVER['REMOTE_ADDR']``` against the resolved address. If it doesn't match, we print "ERROR: Requesting address is REMOTE_ADDR while server is at SERVIP", where REMOTE_ADDR is ```$_SERVER['REMOTE_ADDR']``` and SERVIP is the resolved IP, and then call die().

If it matches, we fetch the server with the matching nameport. If we successfully delete the server, we delete the server and any advertgroups associated with it. Finally, we print "REMOVE: NAMEPORT" where NAMEPORT is the provided nameport input parameter.

#### CHECKTOKENS action

The CHECKTOKENS action uses the following input parameters: checktokens, groups

The checktokens and groups input parameters are each a list of items delimited by a ```\r\n```.  The checktokens values are in the format CALLSIGN@IPADDRESS=TOKEN or CALLSIGN=TOKEN, where CALLSIGN is the player callsign, IPADDRESS is the IPv4 address that the player connected to the remote server using, and TOKEN is the authentication token that they player provided.

For each checktoken value, if a token is found after splitting the value apart, we check if the token is valid using the ```checktoken``` function documented above by passing in the callsign, IP address, token, and group array.

#### GETTOKEN action

The GETTOKEN action uses the following input parameters: callsign, password

This action is used to generate a token for a player, but may not actually get called in normal use. The LIST action is used by the client to generate tokens, even in the case where the client isn't intending to show a list of servers.

This action checks if both the callsign and password are set, and then calls the ```authenticate_player``` function. If player data is returned, it writes out "TOKEN: " followed by the generated token. If false is returned from ```authenticate_player```, then it writes "NOTOK: invalid callsign or password". If the username or password isn't set, the action prints no output.

## Challenges With Current Design

The main issue with our current design is our reliance on a consistent player IP address. Our authentication tokens are tied to the IP address that the request was received from. This prevents the use of IPv6 and CGNAT (Carrier-Grade Network Address Translation), since the address that accessed bzfls isn't necessarily going to be the same as the one that accessed the game server. We don't currently support IPv6 for this reason, but CGNAT has already been causing problems and that technology is becoming more common due to the IPv4 exhaustion.

Related to the first issue is the reliance on IPv4 addressing throughout the code. The hostname of a server must resolve to a single IPv4 address. The IP address is included as part of the LIST action output (although it isn't used by the client).

The third challenge is our tight integration with phpBB. **EXPAND ON THIS**

## Design for replacement system

For 2.5+ clients, the replacement will take the form of a REST or REST-like API making use of well formed JSON. A compatibility layer will produce the expected output for older clients/servers. That would either be integrated directly into the new system, or be a shim layer that transforms the information from the API.

### Changes to authentication token

The big thing is that **we must protect against a rogue server operator stealing tokens to log into other servers as another player**. With the current system, we accomplish this by restricting the use of the token to the IP address that requested it. This, as mentioned above, can't work with IPv6 or CGNAT. So the new method is to request a token for use on a specific server.

Old clients/servers and the weblogin system will continue to use the old bzfls interface. The compatibility layer will need to work with IPv4 address validation for now. The API endpoint to generate a token will store an IPv4 address if accessed through the compatibility layer, and the endpoint to validate tokens will have an IP address parameter to verify that token. Eventually the current weblogin will be replaced with OpenID Connect.

### API Design

See the [API Documentation](https://cs.bzexcess.com/docs/v1/) of the in-development OpenAPI 3 specification.
