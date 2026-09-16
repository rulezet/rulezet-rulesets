rule Trojan_Win32_Injuke_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Injuke.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 03 c8 89 0d e4 cd 46 00 e8 ?? 63 02 00 8b c8 b8 ?? ?? ?? ?? 33 d2 8b 1d c8 ?? 46 00 f7 f1 33 d8 89 1d c8 cc 46 00 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}