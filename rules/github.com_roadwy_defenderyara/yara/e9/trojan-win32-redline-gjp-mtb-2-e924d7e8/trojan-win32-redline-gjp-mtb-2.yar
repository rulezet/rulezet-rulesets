rule Trojan_Win32_Redline_GJP_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 da 88 55 df 0f b6 45 df f7 d0 88 45 df 0f b6 4d df 2b 4d e0 88 4d df 0f b6 55 df f7 d2 88 55 df 0f b6 45 df 03 45 e0 88 45 df 8b 4d e0 8a 55 df 88 54 0d e4 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}