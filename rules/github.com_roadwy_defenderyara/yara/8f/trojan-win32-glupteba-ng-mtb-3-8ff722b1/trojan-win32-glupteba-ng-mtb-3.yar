rule Trojan_Win32_Glupteba_NG_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 d1 31 55 ?? 8b 4d ?? 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 3d [0-04] 26 04 00 00 75 } 		$a_02_1 = {33 d1 31 55 ?? 8b 4d ?? 8d 85 ?? ?? ?? ?? 90 18 29 08 c3 } 		$a_02_2 = {8b c6 d3 e0 8b 8d ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}