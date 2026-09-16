rule Trojan_Win32_RedLineStealer_DF_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 89 18 8b 45 c8 03 45 a0 8b 55 d8 31 02 6a 66 e8 ?? ?? ?? ?? bb 04 00 00 00 2b d8 6a 66 e8 ?? ?? ?? ?? 03 d8 01 5d ec 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}