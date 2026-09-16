rule Trojan_Win32_Ekstak_RK_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 57 68 3e e1 64 00 e8 1e 6e fb ff 8b f8 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}