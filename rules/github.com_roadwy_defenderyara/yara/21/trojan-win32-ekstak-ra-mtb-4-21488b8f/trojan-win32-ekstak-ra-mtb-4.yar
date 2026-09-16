rule Trojan_Win32_Ekstak_RA_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 fb ff 8b f0 e9 90 09 04 00 56 57 e8 } 		$a_01_1 = {40 00 00 40 5f 62 63 6f 72 65 } 		$a_01_2 = {43 00 61 00 74 00 61 00 6c 00 6f 00 67 00 69 00 63 00 20 00 42 00 6f 00 6f 00 6b 00 20 00 4c 00 69 00 73 00 74 00 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}