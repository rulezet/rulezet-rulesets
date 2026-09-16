rule Trojan_Win32_Fragtor_NFR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 00 4d 00 55 00 69 00 2e 00 52 00 75 00 6e 00 } 		$a_01_1 = {69 00 55 00 71 00 6d 00 2e 00 72 00 65 00 70 00 } 		$a_01_2 = {4f 00 57 00 6a 00 75 00 78 00 44 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}