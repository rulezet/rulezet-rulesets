rule ADSync_CredDump_Wide {
meta:
 author = "SBousseaden"
 date = "04-08-2020"
 description = "AD Connect Sync Credential Extract"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $s1 = "private_configuration_xml" wide xor
 $s2 = "LoadKeySet" xor 
 $s3 = "encrypted_configuration" wide xor
 $s4 = "GetActiveCredentialKey" xor
 $s5 = "DecryptBase64ToString" xor
 $s6 = "KeyManager" xor
 $s7 = "(LocalDB)\\.\\ADSync" wide xor
 $s8 = "mms_management_agent" wide xor
 $s9 = "keyset_id" wide xor
 $s10 = "xp_cmdshell" xor
 $s11 = "System.Data.SqlClient"
 $s12 = "Password" wide xor
 $fp1 = "mmsutils\\mmsutils.pdb"
condition: 5 of them and not $fp1
}