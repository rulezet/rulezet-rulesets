rule Trojan_Win32_Azorult_CA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.CA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 81 c4 14 11 00 00 c3 b8 40 1c 00 00 } 		$a_01_1 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 54 0c 00 00 51 ff d7 8d 54 24 28 52 ff d3 8d 44 24 24 50 c7 44 24 28 00 00 00 00 ff d5 6a 00 8d 8c 24 54 14 00 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}