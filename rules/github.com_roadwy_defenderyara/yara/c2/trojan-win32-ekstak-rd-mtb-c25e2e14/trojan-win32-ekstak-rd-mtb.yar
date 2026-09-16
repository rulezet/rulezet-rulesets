rule Trojan_Win32_Ekstak_RD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 e8 97 65 fb ff e8 12 65 fb ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}