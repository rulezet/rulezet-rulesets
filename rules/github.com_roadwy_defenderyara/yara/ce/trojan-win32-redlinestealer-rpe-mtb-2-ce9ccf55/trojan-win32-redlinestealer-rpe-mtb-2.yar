rule Trojan_Win32_RedLineStealer_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb 05 21 bb ?? ?? ?? 50 90 13 e8 17 00 00 00 90 13 90 13 33 c0 eb 02 00 a9 71 64 eb 03 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}