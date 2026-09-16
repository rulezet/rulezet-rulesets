rule Trojan_Win32_Emotet_GB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 4d fc 8b 55 08 c7 45 fc 75 e4 00 00 c1 6d fc 09 83 75 fc 62 d3 e2 8a 4d fc } 		$a_01_1 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } 		$a_01_2 = {52 75 6e 44 4c 4c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}