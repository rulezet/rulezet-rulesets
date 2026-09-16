rule Trojan_Win32_Ekstak_RF_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 8b 75 14 6a 00 6a 00 56 ff 15 ?? e4 46 00 56 ff 15 ?? e4 46 00 ff 15 ?? e4 46 00 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}