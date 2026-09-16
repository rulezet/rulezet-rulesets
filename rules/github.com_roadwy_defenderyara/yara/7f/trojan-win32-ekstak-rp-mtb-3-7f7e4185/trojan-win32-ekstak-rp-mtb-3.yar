rule Trojan_Win32_Ekstak_RP_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 e8 1a 72 fb ff 8b f0 e9 } 		$a_01_1 = {40 00 00 40 5f 74 61 62 6c 65 5f } 		$a_01_2 = {40 00 00 40 2e 6d 70 65 67 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}