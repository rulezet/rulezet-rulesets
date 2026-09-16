rule Trojan_Win32_Vidar_MD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d f0 8b 45 f4 8b 4d f8 03 c7 d3 ef 89 45 e4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 7d d8 8b 45 e4 31 45 fc 33 7d fc } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}