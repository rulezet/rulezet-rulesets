rule Trojan_Win32_Raccoon_RE_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 4c 24 2c 89 35 ?? ?? ?? ?? 31 4c 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 40 29 44 24 18 } 		$a_03_1 = {81 01 e1 34 ef c6 c3 [0-15] 01 11 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}