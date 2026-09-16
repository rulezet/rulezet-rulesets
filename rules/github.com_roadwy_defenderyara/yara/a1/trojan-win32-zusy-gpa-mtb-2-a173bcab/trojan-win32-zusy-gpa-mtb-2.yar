rule Trojan_Win32_Zusy_GPA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d0 03 55 f8 0f b6 02 83 f0 57 8b 4d e4 03 4d f8 88 01 eb 52 8b 45 f8 33 d2 b9 03 00 00 00 f7 f1 83 fa 01 75 16 8b 55 d0 03 55 f8 0f b6 02 83 f0 77 8b 4d e4 03 4d f8 88 01 eb 2b 8b 45 f8 33 d2 b9 03 00 00 00 f7 f1 83 fa 02 75 1a 8b 55 d0 03 55 f8 0f b6 02 83 f0 36 0f b6 4d f8 33 c1 8b 55 e4 03 55 f8 88 02 e9 72 ff ff ff } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}