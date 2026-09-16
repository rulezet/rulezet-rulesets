rule Trojan_Win32_Redline_GMI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 f4 8a 02 88 45 fe 0f b6 4d fe 8b 45 f4 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}