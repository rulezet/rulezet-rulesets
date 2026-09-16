rule Trojan_Win32_Redline_ARD_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 56 57 c6 45 ?? 93 c6 45 ?? f4 c6 45 ?? 45 c6 45 ?? a5 c6 45 ?? b5 c6 45 ?? 44 c6 45 ?? 25 c6 45 ?? 73 c6 45 ?? 45 c6 45 ?? 15 c6 45 ?? a5 c6 45 ?? 84 c6 45 ?? 64 c6 45 ?? a5 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}