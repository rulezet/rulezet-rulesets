rule Trojan_Win32_Redline_GNT_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 4a 02 c1 e1 10 0f be 42 01 c1 e0 08 33 c8 0f be 02 33 c1 69 c0 ?? ?? ?? ?? 33 f8 8b c7 c1 e8 0d 33 c7 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 0f 33 c8 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}