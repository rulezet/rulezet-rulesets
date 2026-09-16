rule Trojan_Win32_Ekstak_RA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 d8 67 fb ff eb 0d 8b 75 fc e8 ce 67 fb ff eb 03 8b 75 fc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}