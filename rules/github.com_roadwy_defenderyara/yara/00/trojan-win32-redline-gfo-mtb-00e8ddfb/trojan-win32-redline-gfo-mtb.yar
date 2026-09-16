rule Trojan_Win32_Redline_GFO_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 33 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 c1 88 45 d3 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}