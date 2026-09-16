rule Trojan_Win32_ClickFix_IIO_MTB_3{
	meta:
		description = "Trojan:Win32/ClickFix.IIO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } 		$a_00_1 = {2e 00 6a 00 70 00 67 00 7c 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 3b 00 24 00 } 		$a_00_2 = {2e 00 6a 00 70 00 67 00 7c 00 49 00 65 00 78 00 3b 00 24 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=11
 
}