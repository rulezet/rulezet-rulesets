rule Trojan_Win32_Vidar_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 69 d2 fd 43 03 00 81 c2 c3 9e 26 00 89 15 14 ?? 45 00 8a 0d 16 ?? 45 00 30 0c 30 83 ff 0f 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}