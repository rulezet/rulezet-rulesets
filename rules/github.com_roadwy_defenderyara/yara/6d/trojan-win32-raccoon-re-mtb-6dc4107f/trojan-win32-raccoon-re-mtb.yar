rule Trojan_Win32_Raccoon_RE_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb b2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}