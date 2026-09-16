rule Trojan_Win32_Redline_TS_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c8 88 45 ?? 0f b6 4d ?? 31 c0 29 c8 88 45 ?? 8b 4d ?? 0f b6 45 ?? 31 c8 88 45 ?? 0f b6 45 ?? 83 e8 ?? 88 45 ?? 0f b6 45 ?? c1 f8 } 		$a_00_1 = {35 f1 00 00 00 88 45 e3 8a 4d e3 8b 45 e4 88 4c 05 e9 } 	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}