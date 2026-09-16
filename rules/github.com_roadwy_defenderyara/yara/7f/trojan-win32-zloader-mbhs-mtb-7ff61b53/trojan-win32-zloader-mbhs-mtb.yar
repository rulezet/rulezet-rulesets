rule Trojan_Win32_Zloader_MBHS_MTB{
	meta:
		description = "Trojan:Win32/Zloader.MBHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 72 63 74 76 79 62 44 72 63 74 76 79 } 		$a_01_1 = {59 63 74 76 79 62 45 63 72 74 76 79 } 		$a_01_2 = {66 72 67 74 68 79 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}