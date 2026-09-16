rule Trojan_BAT_RedLine_MH_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 } 		$a_01_1 = {39 38 61 34 32 61 31 35 2d 63 31 36 65 2d 34 35 63 65 2d 62 34 62 63 2d 63 30 35 64 30 34 65 38 32 66 31 66 } 		$a_01_2 = {4d 69 6e 65 73 77 65 65 70 65 72 5f 57 69 6e 64 6f 77 73 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}