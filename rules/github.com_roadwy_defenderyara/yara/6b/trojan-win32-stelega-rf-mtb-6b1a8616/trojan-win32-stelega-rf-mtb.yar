rule Trojan_Win32_Stelega_RF_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 89 f7 e8 ?? ?? ?? ?? 01 f6 01 f6 09 f6 31 03 81 ee 80 d8 7d d6 01 ff 81 ee } 		$a_00_1 = {81 c1 62 fe 43 51 81 e9 01 00 00 00 31 1f be 63 a3 dc 61 81 e9 30 31 01 56 f7 d1 47 89 c1 f7 d1 89 f1 81 c2 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}