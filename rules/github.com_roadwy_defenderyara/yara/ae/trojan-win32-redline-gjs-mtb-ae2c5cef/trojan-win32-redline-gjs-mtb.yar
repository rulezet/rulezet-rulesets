rule Trojan_Win32_Redline_GJS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {3c d3 40 00 c7 45 ?? 35 45 00 00 c7 85 ?? ?? ?? ?? 48 d3 40 00 c6 45 ?? 77 c7 85 ?? ?? ?? ?? 60 d3 40 00 c7 85 ?? ?? ?? ?? 68 09 00 00 c7 85 ?? ?? ?? ?? 7c d3 40 00 b9 af 6e 00 00 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}