rule Trojan_BAT_Tedy_NTY_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.NTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7b 02 00 00 0a 0a 12 00 25 71 ?? 00 00 1b 8c ?? 00 00 1b 3a ?? 00 00 00 26 14 38 ?? 00 00 00 fe ?? ?? ?? ?? 1b 6f ?? 00 00 0a a2 25 17 02 7b ?? 00 00 0a } 		$a_01_1 = {63 72 75 7a 7a 61 32 38 47 76 66 69 78 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}