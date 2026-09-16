rule Trojan_Win32_Ekstak_RC_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 57 68 5f bf 65 00 e8 a0 55 fb ff 8b f0 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}