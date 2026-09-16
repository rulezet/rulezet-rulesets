rule Trojan_Win32_Neoreblamy_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 62 41 59 6f 63 79 78 6d 61 72 7a 46 74 51 79 6c } 		$a_01_1 = {51 76 52 61 77 69 71 67 6c 67 58 } 		$a_01_2 = {64 4c 57 62 4c 78 6c 69 6f 58 4f 4d 46 52 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}