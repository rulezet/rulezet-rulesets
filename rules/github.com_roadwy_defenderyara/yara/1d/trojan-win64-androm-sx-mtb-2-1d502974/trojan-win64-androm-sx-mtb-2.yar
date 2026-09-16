rule Trojan_Win64_Androm_SX_MTB_2{
	meta:
		description = "Trojan:Win64/Androm.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_03_0 = {f3 43 0f 6f 04 28 48 63 c1 83 c2 ?? 83 c1 ?? 48 8d 7f ?? 66 0f ef c6 f3 43 0f 7f 04 28 f3 42 0f 6f 04 28 4c 63 c2 66 0f ef c6 f3 42 0f 7f 04 28 } 		$a_03_1 = {45 33 c0 33 c9 49 f7 e4 48 d1 ea 48 8d 04 52 41 8d 51 ?? 4c 2b e0 48 8d 44 24 ?? 41 8b fc 48 89 44 24 ?? 48 c1 e7 ?? 48 03 fb } 		$a_80_2 = {5c 57 65 72 46 61 75 6c 74 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1) >=16
 
}