rule Trojan_Win32_Ekstak_RF_MTB_8{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 56 8b 7d 14 6a 03 e8 ?? ?? 04 00 59 e9 ?? ?? ?? 00 } 		$a_01_1 = {2e 69 6d 67 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}