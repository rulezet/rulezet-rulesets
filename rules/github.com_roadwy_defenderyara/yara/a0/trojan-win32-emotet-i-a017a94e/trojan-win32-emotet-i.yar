rule Trojan_Win32_Emotet_I{
	meta:
		description = "Trojan:Win32/Emotet.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 68 40 23 23 77 65 68 2e 50 64 62 } 		$a_00_1 = {52 53 44 53 } 		$a_03_2 = {55 89 e5 50 b8 ?? ?? ?? ?? 31 c9 89 c2 81 ea e8 03 00 00 0f 47 c8 89 c8 89 55 fc 83 c4 04 5d c3 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}