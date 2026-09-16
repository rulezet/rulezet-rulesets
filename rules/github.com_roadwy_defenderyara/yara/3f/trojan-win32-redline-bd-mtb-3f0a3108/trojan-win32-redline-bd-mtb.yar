rule Trojan_Win32_RedLine_BD_MTB{
	meta:
		description = "Trojan:Win32/RedLine.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 ?? 03 fe 31 7d ?? 50 89 45 ?? 8d 45 ?? 50 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}