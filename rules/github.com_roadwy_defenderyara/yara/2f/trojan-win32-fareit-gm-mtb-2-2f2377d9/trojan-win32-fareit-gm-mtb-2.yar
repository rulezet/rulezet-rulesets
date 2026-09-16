rule Trojan_Win32_Fareit_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 83 e1 [0-30] 8a 0a 80 f1 4a 8b 5d ?? 03 d8 88 0b [0-30] 8b 4d ?? 03 c8 8a 1a 88 19 40 42 3d } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}