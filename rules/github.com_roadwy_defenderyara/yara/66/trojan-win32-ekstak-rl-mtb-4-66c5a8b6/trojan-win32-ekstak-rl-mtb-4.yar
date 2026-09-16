rule Trojan_Win32_Ekstak_RL_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 68 0e df 64 00 e8 be 6f fb ff 8b f8 e9 } 		$a_01_1 = {55 8b ec 83 ec 08 56 57 68 ee de 64 00 e8 ee 6f fb ff 8b f8 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}