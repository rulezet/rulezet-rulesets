rule Trojan_Win32_Ekstak_RC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 68 24 1f 65 00 e8 42 65 fb ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}