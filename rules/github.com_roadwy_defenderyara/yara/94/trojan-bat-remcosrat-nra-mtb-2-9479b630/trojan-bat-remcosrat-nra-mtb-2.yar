rule Trojan_BAT_RemcosRAT_NRA_MTB_2{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 0c 00 00 0a 13 20 11 1a 73 ?? ?? 00 0a 13 21 11 21 11 20 16 73 ?? ?? 00 0a 13 22 11 22 28 ?? ?? 00 0a 73 ?? ?? 00 0a 13 23 11 14 6f ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 13 24 11 23 6f ?? ?? 00 0a 28 ?? ?? 00 0a } 		$a_01_1 = {65 00 5a 00 59 00 57 00 77 00 45 00 4a 00 52 00 6e 00 42 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}