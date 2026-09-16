rule Trojan_Win32_Ekstak_RF_MTB_11{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c7 84 24 20 01 00 00 53 58 58 53 c3 55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 6a 03 e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}