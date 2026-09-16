rule Trojan_Win32_SmokeLoader_RE_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3 } 		$a_03_1 = {36 dd 96 53 81 45 ?? 38 dd 96 53 8b 55 ?? 8b 4d ?? 8b c2 d3 e0 [0-40] 8b c2 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 f8 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}