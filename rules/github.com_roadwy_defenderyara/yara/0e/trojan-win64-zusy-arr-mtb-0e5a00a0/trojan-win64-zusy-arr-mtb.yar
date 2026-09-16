rule Trojan_Win64_Zusy_ARR_MTB{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 79 65 63 74 6f 31 } 		$a_01_1 = {00 4f 70 65 6e 48 74 6d 6c } 		$a_01_2 = {00 2b 33 71 b5 02 00 00 00 } 	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2) >=20
 
}