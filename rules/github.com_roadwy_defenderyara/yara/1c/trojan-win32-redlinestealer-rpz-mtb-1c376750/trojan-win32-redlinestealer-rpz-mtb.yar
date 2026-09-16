rule Trojan_Win32_RedLineStealer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 db b8 11 00 00 00 83 c0 1f 64 8b 3c 03 8b 7f 0c 8b 77 14 8b 36 8b 36 8b 46 10 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}