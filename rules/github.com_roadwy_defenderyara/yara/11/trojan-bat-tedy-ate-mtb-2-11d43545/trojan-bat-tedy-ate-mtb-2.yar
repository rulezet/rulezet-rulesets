rule Trojan_BAT_Tedy_ATE_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 12 04 28 ?? ?? ?? 0a 0d 1e 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 09 a2 25 18 72 ?? ?? ?? 70 a2 25 19 07 a2 25 1a 72 ?? ?? ?? 70 a2 25 1b 08 a2 25 1c 72 ?? ?? ?? 70 a2 25 1d 06 a2 } 		$a_01_1 = {76 74 5f 74 65 73 74 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 76 74 5f 74 65 73 74 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}