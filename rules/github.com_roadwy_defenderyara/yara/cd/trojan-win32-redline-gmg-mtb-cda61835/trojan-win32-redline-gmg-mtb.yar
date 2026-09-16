rule Trojan_Win32_Redline_GMG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 f4 80 c9 7b 22 ff 80 cf 3a 0a ff c0 e7 1c 80 e4 5e 66 0b da b6 74 66 23 d0 66 c1 e2 34 80 e6 3d b5 0c 80 f4 68 c7 44 24 ?? ?? ?? ?? ?? 66 0b d8 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}