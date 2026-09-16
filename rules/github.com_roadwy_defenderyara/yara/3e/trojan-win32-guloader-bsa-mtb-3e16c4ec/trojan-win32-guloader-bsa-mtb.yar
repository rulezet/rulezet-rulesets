rule Trojan_Win32_Guloader_BSA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_81_0 = {6c 61 67 65 72 65 2e 65 78 65 } 		$a_81_1 = {70 61 72 69 64 69 67 69 74 61 74 65 20 64 65 6e 74 6e 69 6e 67 65 72 } 		$a_81_2 = {75 6e 63 69 72 6f 73 74 72 61 74 65 20 70 6f 73 74 67 6c 65 6e 6f 69 64 61 6c } 	condition:
		((#a_81_0  & 1)*15+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5) >=25
 
}