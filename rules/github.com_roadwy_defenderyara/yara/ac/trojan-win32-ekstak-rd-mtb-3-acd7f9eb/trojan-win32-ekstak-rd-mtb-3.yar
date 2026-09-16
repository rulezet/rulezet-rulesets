rule Trojan_Win32_Ekstak_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 68 34 2f 65 00 e8 c2 64 fb ff e8 8d 65 fb ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}