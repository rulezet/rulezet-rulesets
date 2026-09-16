rule Ransom_Win32_GandCrab_AD_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 1e 35 71 87 fb 3c 81 ?? ?? 20 b9 00 6b 81 ?? ?? 20 b9 00 6b 81 ?? ?? 5a ce 13 12 81 ?? ?? 72 23 32 5d 81 ?? ?? cc f1 45 6f c1 ?? 03 } 		$a_02_1 = {c1 e8 1e 35 71 87 fb 3c 90 08 00 04 c6 05 ?? ?? ?? ?? 6b } 	condition:
		((#a_02_0  & 1)*4+(#a_02_1  & 1)*1) >=4
 
}