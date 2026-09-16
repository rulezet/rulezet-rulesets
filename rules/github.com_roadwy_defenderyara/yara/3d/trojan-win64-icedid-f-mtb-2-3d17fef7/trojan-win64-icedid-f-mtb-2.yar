rule Trojan_Win64_IcedID_F_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 61 73 66 75 68 6b 61 73 66 69 61 6a 73 6b 66 } 		$a_01_1 = {67 6c 79 70 68 2d 61 72 72 6f 77 2d 68 74 6d 6c } 		$a_01_2 = {2e 73 68 74 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}