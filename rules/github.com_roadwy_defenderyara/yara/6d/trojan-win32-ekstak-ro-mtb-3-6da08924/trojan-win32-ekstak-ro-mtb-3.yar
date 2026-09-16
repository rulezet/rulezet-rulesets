rule Trojan_Win32_Ekstak_RO_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 68 01 ef 64 00 e8 a5 71 fb ff 8b f0 e9 } 		$a_01_1 = {56 e8 ca 71 fb ff 8b f0 e9 } 		$a_01_2 = {40 00 00 40 2e 74 61 62 6c 65 } 		$a_01_3 = {40 00 00 40 5f 74 61 62 6c 65 5f } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}