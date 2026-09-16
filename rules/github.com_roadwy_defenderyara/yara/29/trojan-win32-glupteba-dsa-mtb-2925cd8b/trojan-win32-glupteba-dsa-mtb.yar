rule Trojan_Win32_Glupteba_DSA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c0 7b 56 8b f2 89 44 24 04 } 		$a_01_1 = {8b 54 24 04 8a 04 32 88 04 31 5e 81 c4 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}