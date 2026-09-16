rule Trojan_Win32_Ekstak_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 68 84 a0 65 00 e8 45 57 fb ff 8b f0 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}