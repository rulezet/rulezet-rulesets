rule Trojan_BAT_Remcos_AR_MTB_18{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 3b 09 17 8d ?? ?? ?? 01 25 16 08 17 8d ?? ?? ?? 01 25 16 11 04 8c ?? ?? ?? 01 a2 14 28 } 		$a_01_1 = {50 00 6f 00 6b 00 65 00 6d 00 6f 00 6e 00 41 00 70 00 70 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}