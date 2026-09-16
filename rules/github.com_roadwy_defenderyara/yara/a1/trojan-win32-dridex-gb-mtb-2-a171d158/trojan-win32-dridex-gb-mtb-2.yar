rule Trojan_Win32_Dridex_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_00_0 = {89 74 24 0c 89 4c 24 08 89 54 24 04 8d 65 f4 } 		$a_02_1 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } 		$a_80_2 = {74 74 74 74 33 32 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=21
 
}