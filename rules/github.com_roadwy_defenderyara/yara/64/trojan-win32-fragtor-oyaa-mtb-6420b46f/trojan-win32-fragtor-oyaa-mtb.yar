rule Trojan_Win32_Fragtor_OYAA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.OYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 73 61 6f 69 67 66 61 73 69 6f 67 6a 6b } 		$a_01_1 = {47 73 6f 69 67 6a 73 65 6f 69 67 73 65 6a 69 67 6a 69 } 		$a_01_2 = {4e 73 67 66 6f 69 73 6a 67 66 6f 73 69 65 67 6f 69 73 6a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}