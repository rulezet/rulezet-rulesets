rule Trojan_Win32_Redline_GNB_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e6 66 c1 df fa 66 81 ca cc 00 66 f7 e1 33 d8 81 ee ?? ?? ?? ?? 8b fe 66 0b db c1 e7 5a 03 d9 0f bf d2 8b c7 66 f7 e0 66 03 f0 42 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}