rule Trojan_BAT_AsyncRAT_ARAZ_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRAT.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {78 75 5a 69 54 71 67 64 64 75 42 78 69 73 78 55 50 4d 46 30 47 37 41 33 6b 6a 37 53 78 38 57 4c } 		$a_03_1 = {00 06 07 02 07 91 28 ?? ?? ?? 0a 9d 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e5 } 		$a_01_2 = {2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_80_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}