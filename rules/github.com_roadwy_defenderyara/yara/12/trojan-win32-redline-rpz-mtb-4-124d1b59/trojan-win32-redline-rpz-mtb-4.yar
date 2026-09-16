rule Trojan_Win32_Redline_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 32 04 37 88 45 d3 ba } 		$a_01_1 = {59 0f b6 1c 37 8a c3 02 45 d3 88 04 37 ba } 		$a_01_2 = {59 28 1c 37 46 8b 45 c8 eb b1 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}