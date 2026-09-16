rule Trojan_Win32_Ekstak_RH_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 56 57 68 04 01 00 00 6a 00 68 a8 ee 4c 00 e8 fc 01 00 00 83 c4 0c e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}