rule Trojan_BAT_Razy_ARA_MTB{
	meta:
		description = "Trojan:BAT/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 10 11 04 07 08 9a 6f ?? ?? ?? 0a 13 04 08 17 ?? 0c 08 11 05 31 eb 11 04 07 08 9a } 		$a_01_1 = {4c 00 61 00 6e 00 7a 00 61 00 64 00 6f 00 72 00 } 		$a_01_2 = {50 00 61 00 69 00 6c 00 61 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}