rule Trojan_Win32_OffLoader_EM_MTB_2{
	meta:
		description = "Trojan:Win32/OffLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 00 61 00 2e 00 6c 00 6f 00 63 00 6b 00 73 00 74 00 61 00 72 00 74 00 2e 00 68 00 6f 00 73 00 74 00 2f 00 77 00 77 00 2e 00 70 00 68 00 70 00 3f 00 70 00 3d 00 33 00 37 } 		$a_01_1 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65 00 } 	condition:
		((#a_01_0  & 1)*9+(#a_01_1  & 1)*1) >=10
 
}