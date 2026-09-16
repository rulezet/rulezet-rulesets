rule Trojan_Win64_Icedid_EK_MTB_2{
	meta:
		description = "Trojan:Win64/Icedid.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 0f a4 cf 26 48 69 f6 21 09 00 00 e4 3f e4 b1 48 81 c5 83 0c 00 00 e6 90 48 c1 ef 8f 48 8b 04 24 } 		$a_01_1 = {62 68 6a 61 64 73 67 76 74 79 61 73 68 6a 6b } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}