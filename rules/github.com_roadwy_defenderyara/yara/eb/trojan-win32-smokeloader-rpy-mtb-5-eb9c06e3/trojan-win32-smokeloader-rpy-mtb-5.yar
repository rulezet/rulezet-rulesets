rule Trojan_Win32_SmokeLoader_RPY_MTB_5{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 6a 40 8b 85 58 ff ff ff ff 70 0a ff b5 50 ff ff ff ff 55 d8 89 45 f4 8b 85 50 ff ff ff 89 85 68 ff ff ff 8b 85 58 ff ff ff ff 70 0a 6a 00 ff b5 50 ff ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}