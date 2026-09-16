rule Trojan_Win32_Zusy_A_MTB{
	meta:
		description = "Trojan:Win32/Zusy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe 7e 07 00 00 72 e4 33 f6 ff d7 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe 00 76 00 00 72 e4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}