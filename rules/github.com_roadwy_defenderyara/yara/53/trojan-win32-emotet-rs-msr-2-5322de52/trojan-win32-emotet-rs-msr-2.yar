rule Trojan_Win32_Emotet_RS_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.RS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 33 f2 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 } 		$a_02_1 = {b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 b8 c6 01 00 00 8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 5e 8b e5 5d } 		$a_01_2 = {78 72 4d 6f 66 72 72 49 6a } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}