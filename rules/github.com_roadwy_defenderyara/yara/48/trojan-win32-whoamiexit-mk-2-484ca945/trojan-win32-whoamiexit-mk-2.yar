rule Trojan_Win32_WhoAmiExit_MK_2{
	meta:
		description = "Trojan:Win32/WhoAmiExit.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 62 00 5f 00 } 		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 6e 00 75 00 6c 00 } 		$a_00_2 = {77 00 68 00 6f 00 61 00 6d 00 69 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}