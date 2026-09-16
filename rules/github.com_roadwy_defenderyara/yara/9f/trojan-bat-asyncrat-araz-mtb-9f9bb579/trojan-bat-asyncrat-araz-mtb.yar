rule Trojan_BAT_AsyncRAT_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {76 62 4d 6b 53 37 5a 6c 65 66 76 } 		$a_01_1 = {7b 31 61 30 33 65 34 34 30 2d 33 32 39 37 2d 34 38 34 34 2d 38 61 38 34 2d 63 61 33 37 31 65 64 64 33 66 39 30 7d } 		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } 	condition:
		((#a_80_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}