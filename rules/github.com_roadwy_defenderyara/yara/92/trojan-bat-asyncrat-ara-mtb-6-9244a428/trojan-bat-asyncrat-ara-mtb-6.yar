rule Trojan_BAT_AsyncRAT_ARA_MTB_6{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 08 9a 13 06 09 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 11 08 17 d6 13 08 11 08 11 09 8e b7 32 d8 } 		$a_01_1 = {66 75 6e 63 63 61 6c 6c 32 32 } 		$a_01_2 = {52 65 44 5f 53 65 63 75 72 69 74 79 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}