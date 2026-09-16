rule Trojan_Win32_Lazy_MKD_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 46 50 6f 77 65 72 5f 33 32 2e 64 6c 6c } 		$a_01_1 = {56 46 50 6f 77 65 72 5f 33 32 } 		$a_81_2 = {59 6f 75 72 53 68 61 72 65 64 53 65 63 72 65 74 4b 65 79 } 		$a_81_3 = {4b 45 59 5f 42 4f 41 52 44 5f 44 41 54 41 } 		$a_81_4 = {4b 45 59 5f 42 4f 41 52 44 5f 44 41 54 41 5f 4d 44 35 } 	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=35
 
}