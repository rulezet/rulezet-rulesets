rule Trojan_Win32_Offloader_AMBC_MTB{
	meta:
		description = "Trojan:Win32/Offloader.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 73 68 6f 70 62 65 61 64 2e 6f 6e 6c 69 6e 65 2f 62 61 72 74 2e 70 68 70 } 		$a_80_1 = {3a 2f 2f 73 6d 65 6c 6c 63 69 72 63 6c 65 2e 73 69 74 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 } 		$a_80_2 = {2f 73 69 6c 65 6e 74 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}