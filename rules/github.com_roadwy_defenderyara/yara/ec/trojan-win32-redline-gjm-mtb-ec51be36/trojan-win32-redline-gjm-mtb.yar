rule Trojan_Win32_Redline_GJM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 df 0f b6 4d df c1 f9 02 0f b6 55 df c1 e2 06 0b ca 88 4d df 0f b6 45 df 03 45 e0 88 45 df 0f b6 4d df f7 d1 88 4d df 0f b6 55 df c1 fa 05 0f b6 45 df c1 e0 03 0b d0 88 55 df 8b 4d e0 8a 55 df 88 54 0d e4 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}