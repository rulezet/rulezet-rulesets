rule Trojan_Win32_Redline_GTI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 50 e8 ?? ?? ?? ?? 33 d2 8a 1c 33 8b c6 8b 4c 24 18 f7 75 08 83 c4 0c 8a 82 ?? ?? ?? ?? 32 c3 88 44 24 ?? 02 c3 88 04 31 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}