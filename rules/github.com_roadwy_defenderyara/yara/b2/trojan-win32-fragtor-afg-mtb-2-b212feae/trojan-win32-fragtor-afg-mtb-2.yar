rule Trojan_Win32_Fragtor_AFG_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.AFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 48 8f 50 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 48 8f 50 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}