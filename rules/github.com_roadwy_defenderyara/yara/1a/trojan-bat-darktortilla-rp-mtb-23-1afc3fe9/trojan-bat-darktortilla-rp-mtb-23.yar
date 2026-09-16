rule Trojan_BAT_DarkTortilla_RP_MTB_23{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 17 da 17 d6 8d ?? ?? 00 01 0b 72 } 		$a_03_1 = {b7 0a 06 17 da 17 d6 8d ?? ?? 00 01 0b 20 ?? ?? ?? ?? 8c ?? ?? 00 01 0c 72 ?? ?? 00 70 72 ?? ?? 00 70 72 ?? ?? 00 70 28 } 		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}