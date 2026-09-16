rule Trojan_Win32_Delfinject_AD_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 6d 4e 6f 74 43 6f 70 79 } 		$a_80_1 = {71 6a 68 74 68 68 70 6b 6a 71 6b 6d 70 69 6c 72 } 		$a_80_2 = {57 69 6e 48 65 6c 70 56 69 65 77 65 72 } 		$a_80_3 = {55 72 6c 4d 6f 6e } 		$a_80_4 = {6d 6b 75 6f 6d 74 6f } 		$a_80_5 = {6b 69 70 69 68 70 68 } 		$a_80_6 = {68 6d 77 68 6e 70 6d } 	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}