rule ADSync_CredDump_XWide {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" wide xor
 $a2 = "LoadKeySet" wide xor
 $a3 = "encrypted_configuration" wide xor
 $a4 = "GetActiveCredentialKey" wide xor
 $a5 = "DecryptBase64ToString" wide xor
 $a6 = "Cryptography.KeyManager" wide xor
 $b1 = "mms_management_agent" wide xor
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" wide xor
 $b3 = "xp_cmdshell" wide xor
 $b4 = "Password" wide xor
 $b5 = "forest-login-user" wide xor
 $b6 = "forest-login-domain" wide xor
condition: 4 of ($a*) or 4 of ($b*)
}