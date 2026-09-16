rule Trojan_Win32_RedLineStealer_PA_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 b9 0a 00 00 00 f7 f1 0f b6 92 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 0f b6 08 33 ca 8b 55 ?? 03 55 ?? 88 0a ff 15 ?? ?? ?? ?? 89 45 ?? eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}