rule Trojan_BAT_Razy_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Razy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 18 73 23 00 00 0a 13 04 09 11 04 6f ?? ?? ?? 0a de 0c 11 04 2c 07 11 04 6f ?? ?? ?? 0a dc 02 7b 0b 00 00 04 28 } 		$a_01_1 = {42 00 6c 00 61 00 63 00 6b 00 42 00 69 00 6e 00 64 00 65 00 72 00 53 00 74 00 75 00 62 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}