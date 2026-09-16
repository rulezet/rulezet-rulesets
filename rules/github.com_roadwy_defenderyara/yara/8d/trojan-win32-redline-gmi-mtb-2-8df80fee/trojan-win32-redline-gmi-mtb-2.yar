rule Trojan_Win32_Redline_GMI_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 de 33 d8 2b fb 8b d7 c1 e2 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 1c 2f } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}