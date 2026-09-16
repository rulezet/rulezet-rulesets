rule Trojan_Win32_Redline_GTD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 8a 14 11 80 f2 42 88 14 01 41 3b 4d fc ?? ?? 8b 4d fc 50 88 1c 08 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}