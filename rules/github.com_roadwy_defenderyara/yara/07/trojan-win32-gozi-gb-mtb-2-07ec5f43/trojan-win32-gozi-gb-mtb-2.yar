rule Trojan_Win32_Gozi_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_00_0 = {34 5c 68 62 0c 02 10 c3 } 		$a_00_1 = {c0 c0 07 68 1b 26 02 10 c3 } 		$a_00_2 = {68 20 d0 01 10 68 20 d0 01 10 b8 a6 31 02 10 ff d0 } 		$a_80_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}