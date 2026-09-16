rule Trojan_Win32_Ekstak_RK_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 e8 23 6e fb ff 8b f8 e9 } 		$a_01_1 = {40 00 00 40 2e 47 49 46 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}