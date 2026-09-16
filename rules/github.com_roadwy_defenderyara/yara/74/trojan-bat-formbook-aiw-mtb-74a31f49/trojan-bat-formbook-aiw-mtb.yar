rule Trojan_BAT_Formbook_AIW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 1f 07 11 06 11 07 6f ?? ?? ?? 0a 13 08 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 07 17 58 13 07 11 07 07 6f ?? ?? ?? 0a 32 d7 11 06 } 		$a_01_1 = {4f 00 50 00 4e 00 31 00 4c 00 57 00 5f 00 76 00 31 00 2e 00 5f 00 31 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}