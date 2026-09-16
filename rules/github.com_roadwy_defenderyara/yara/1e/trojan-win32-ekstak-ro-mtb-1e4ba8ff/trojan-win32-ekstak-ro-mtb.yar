rule Trojan_Win32_Ekstak_RO_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 68 ef de 64 00 e8 45 6f fb ff 8b f0 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}