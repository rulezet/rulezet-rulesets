rule Trojan_Win32_Zenpak_GZX_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 ca d6 41 00 f4 d6 41 00 4f d7 41 00 c6 d7 41 00 fc d7 41 00 46 d8 } 		$a_03_1 = {b5 07 41 00 79 07 41 00 b5 ?? ?? ?? ?? 07 41 00 b5 ?? ?? ?? ?? 07 41 00 79 07 41 00 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 10 83 ec 08 56 8b f0 c1 e8 1d } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}