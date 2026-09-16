rule Trojan_Win32_Ekstak_RF_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 46 07 00 00 59 a3 a0 0b 08 01 e8 9b 07 00 00 8b c8 33 d2 b8 ?? ?? ?? ?? f7 f1 31 05 7c 0b 08 01 e8 ?? 0c 00 00 33 c0 50 50 e8 68 00 00 00 a3 80 0b 08 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}