rule Trojan_Win32_Ekstak_RI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 56 e8 c4 6d fb ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}