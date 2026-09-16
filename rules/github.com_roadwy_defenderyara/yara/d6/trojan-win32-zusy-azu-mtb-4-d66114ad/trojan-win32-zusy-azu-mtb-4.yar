rule Trojan_Win32_Zusy_AZU_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.AZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 c1 fa 08 8b ca c1 e9 1f 03 ca 8b 15 ?? ?? ?? ?? 69 d2 6d 08 00 00 6a 01 68 00 17 45 00 6a 00 2b ce 68 80 16 45 00 2b ca 68 d8 1d 44 00 81 c1 2e 32 00 00 6a 00 } 		$a_03_1 = {03 d1 c1 fa 0c 8b c2 c1 e8 1f 03 c2 8b c8 b8 37 ed b2 a5 f7 ee 8b 35 ?? ?? ?? ?? c1 fa 0a 8b c2 c1 e8 1f 03 c2 2b c1 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}