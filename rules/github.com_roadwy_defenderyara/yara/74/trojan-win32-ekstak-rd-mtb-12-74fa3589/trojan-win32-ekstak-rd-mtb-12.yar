rule Trojan_Win32_Ekstak_RD_MTB_12{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 56 57 68 ?? cf 65 00 e8 ?? 55 fb ff 8b f0 e9 } 		$a_01_1 = {40 00 00 40 5f 65 63 6f 72 65 5f } 		$a_01_2 = {40 00 00 40 2e 65 63 6f 72 65 } 		$a_01_3 = {40 00 00 40 5f 64 63 6f 72 65 5f } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}