rule Trojan_Win32_Fareit_VM_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 52 50 8b 03 99 03 04 24 13 54 24 04 83 c4 ?? c6 00 ?? ff 03 81 3b ?? ?? ?? ?? 75 } 		$a_00_1 = {44 4e 59 39 76 32 44 77 59 6c 37 63 54 55 61 4b 36 69 34 5a 53 68 58 6e 75 4f 63 44 66 6e 6d 70 76 54 } 		$a_03_2 = {68 68 17 47 00 e8 ?? ?? ?? ?? 4b 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}