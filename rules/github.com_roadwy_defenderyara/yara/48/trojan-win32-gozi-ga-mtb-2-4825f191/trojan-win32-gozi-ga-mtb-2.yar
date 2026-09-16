rule Trojan_Win32_Gozi_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_00_0 = {c0 c8 07 68 cd 1b 02 10 c3 } 		$a_00_1 = {34 0d 68 98 ec 01 10 c3 } 		$a_00_2 = {68 2d ad 01 10 68 2d ad 01 10 b8 7c c3 01 10 ff d0 } 		$a_80_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } 	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}