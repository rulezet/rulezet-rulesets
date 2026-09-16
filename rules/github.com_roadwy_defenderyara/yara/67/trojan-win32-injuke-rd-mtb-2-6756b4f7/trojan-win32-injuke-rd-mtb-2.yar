rule Trojan_Win32_Injuke_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Injuke.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 83 e0 03 8a 04 38 30 04 0a 41 8b 46 04 8b 16 2b c2 3b c8 72 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}