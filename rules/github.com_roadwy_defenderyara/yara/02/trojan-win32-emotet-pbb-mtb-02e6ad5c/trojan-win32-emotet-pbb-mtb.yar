rule Trojan_Win32_Emotet_PBB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 72 73 73 73 73 73 73 } 		$a_01_3 = {5c 77 69 6e 68 6c 70 33 32 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=3
 
}