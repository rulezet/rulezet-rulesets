rule Trojan_Win32_Vidar_MA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 06 89 45 fc 33 d2 8b c3 6a ?? 59 f7 f1 8b 4d fc 8a 04 0a 8b 4d 0c 30 04 1f 43 8b 41 04 8b 39 2b c7 3b d8 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}