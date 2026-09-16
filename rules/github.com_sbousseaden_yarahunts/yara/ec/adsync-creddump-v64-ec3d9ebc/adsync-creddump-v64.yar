rule ADSync_CredDump_v64 {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" base64
 $a2 = "LoadKeySet" base64
 $a3 = "encrypted_configuration" base64
 $a4 = "GetActiveCredentialKey" base64
 $a5 = "DecryptBase64ToString" base64
 $a6 = "Cryptography.KeyManager" base64
 $b1 = "mms_management_agent" base64
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" base64
 $b3 = "xp_cmdshell" base64
 $b4 = "Password" base64
 $b5 = "forest-login-user" base64
 $b6 = "forest-login-domain" base64
condition: 4 of ($a*) or 4 of ($b*)
}