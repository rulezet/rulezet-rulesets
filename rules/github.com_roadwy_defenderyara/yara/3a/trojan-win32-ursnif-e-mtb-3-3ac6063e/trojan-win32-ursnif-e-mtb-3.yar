rule Trojan_Win32_Ursnif_E_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {c6 00 6b c6 40 01 65 c6 40 02 72 c6 40 03 6e c6 40 04 65 c6 40 05 6c c6 40 06 33 } 		$a_00_1 = {c7 03 48 65 61 70 66 c7 43 04 43 72 66 c7 43 06 65 61 } 		$a_80_2 = {6a 72 72 6d 72 72 79 72 6a 67 79 6e } 		$a_80_3 = {72 72 6d 72 72 79 72 6a 67 79 6e } 		$a_80_4 = {71 77 6c 6c 6a 69 75 70 71 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}