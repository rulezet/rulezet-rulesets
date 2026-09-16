rule Trojan_Win32_Azorult_CB_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.CB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 3d 9d 06 00 00 74 12 40 3d c6 7c 13 01 89 44 24 14 0f 8c c2 fe ff ff eb 0c } 		$a_01_1 = {33 c9 33 c0 8d 54 24 20 52 66 89 44 24 14 66 89 4c 24 16 8b 44 24 14 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}