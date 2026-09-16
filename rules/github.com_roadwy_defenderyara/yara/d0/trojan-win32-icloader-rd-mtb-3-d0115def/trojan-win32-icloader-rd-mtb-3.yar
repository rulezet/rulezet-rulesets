rule Trojan_Win32_ICLoader_RD_MTB_3{
	meta:
		description = "Trojan:Win32/ICLoader.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 5e 5b 5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 57 e9 } 		$a_01_1 = {43 00 6f 00 72 00 74 00 65 00 78 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}