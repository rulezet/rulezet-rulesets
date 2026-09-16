rule Trojan_Win32_Redline_GNS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 3e 8b c6 f7 74 24 1c 55 55 8a 82 ?? ?? ?? ?? 32 c3 fe c8 02 c3 88 04 3e ff 15 ?? ?? ?? ?? 28 1c 3e 55 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}