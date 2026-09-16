rule ADSync_CredDump_Xor {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" xor
 $a2 = "LoadKeySet" xor
 $a3 = "encrypted_configuration" xor
 $a4 = "GetActiveCredentialKey" xor
 $a5 = "DecryptBase64ToString" xor
 $a6 = "Cryptography.KeyManager" xor
 $b1 = "mms_management_agent" xor
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" xor
 $b3 = "xp_cmdshell" xor
 $b4 = "Password" xor
 $b5 = "forest-login-user" xor
 $b6 = "forest-login-domain" xor
condition: 4 of ($a*) or 4 of ($b*)
}