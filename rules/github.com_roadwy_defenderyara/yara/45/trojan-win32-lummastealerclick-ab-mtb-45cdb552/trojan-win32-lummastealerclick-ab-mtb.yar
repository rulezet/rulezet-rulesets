rule Trojan_Win32_LummaStealerClick_AB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.AB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } 		$a_00_1 = {68 00 74 00 74 00 70 00 } 		$a_00_2 = {2e 00 6e 00 61 00 6d 00 65 00 } 		$a_00_3 = {2e 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 7c 00 67 00 65 00 74 00 2d 00 6d 00 65 00 6d 00 62 00 65 00 72 00 7c 00 77 00 68 00 65 00 72 00 65 00 7b 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}