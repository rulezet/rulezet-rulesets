rule Trojan_Win32_Ekstak_RC_MTB_18{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 56 8b 7d 14 3b 7d 0c a9 00 00 80 00 57 e8 ?? 8d 06 00 e9 } 		$a_01_1 = {43 00 4a 00 6e 00 67 00 42 00 61 00 63 00 6b 00 75 00 70 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}