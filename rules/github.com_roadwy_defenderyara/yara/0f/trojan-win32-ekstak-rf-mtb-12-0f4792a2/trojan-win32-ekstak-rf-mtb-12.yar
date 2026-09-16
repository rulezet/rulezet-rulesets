rule Trojan_Win32_Ekstak_RF_MTB_12{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 ?? ?? ?? ?? ?? 55 8b ec 56 8b 75 14 56 e8 ?? 9f 20 00 ff 15 ?? ?? 65 00 e9 } 		$a_01_1 = {53 00 6d 00 61 00 72 00 74 00 20 00 54 00 75 00 72 00 6e 00 20 00 4f 00 66 00 66 00 20 00 43 00 4f 00 4d 00 70 00 75 00 74 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}