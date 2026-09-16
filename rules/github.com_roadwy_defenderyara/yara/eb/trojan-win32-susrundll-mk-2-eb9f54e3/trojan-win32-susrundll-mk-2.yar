rule Trojan_Win32_SusRunDll_MK_2{
	meta:
		description = "Trojan:Win32/SusRunDll.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } 		$a_00_1 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 } 		$a_00_2 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 5f 00 6d 00 61 00 69 00 6e 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}