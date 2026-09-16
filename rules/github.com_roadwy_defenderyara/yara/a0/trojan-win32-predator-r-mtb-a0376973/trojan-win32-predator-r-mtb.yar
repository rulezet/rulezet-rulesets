rule Trojan_Win32_Predator_R_MTB{
	meta:
		description = "Trojan:Win32/Predator.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 ff d7 ff d3 81 fe [0-04] 7e 12 81 7d [0-05] 74 09 81 7d [0-05] 75 0b 46 81 fe [0-04] 7c d1 } 		$a_02_1 = {88 14 01 40 3b 05 ?? ?? ?? ?? 72 e1 90 09 13 00 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}