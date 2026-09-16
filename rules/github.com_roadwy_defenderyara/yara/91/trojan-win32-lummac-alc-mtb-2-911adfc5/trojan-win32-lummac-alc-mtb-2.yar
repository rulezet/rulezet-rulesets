rule Trojan_Win32_LummaC_ALC_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 50 6a 4b 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 50 6a 4b 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}