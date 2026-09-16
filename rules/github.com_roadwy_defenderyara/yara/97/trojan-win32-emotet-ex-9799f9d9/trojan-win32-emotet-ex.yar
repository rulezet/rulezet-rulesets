rule Trojan_Win32_Emotet_EX{
	meta:
		description = "Trojan:Win32/Emotet.EX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {85 ff 74 22 29 c9 49 23 0a 83 c2 04 83 c1 ee 31 d9 8d 49 ff 89 cb 89 4e 00 83 ef 04 83 ee fc b9 ?? ?? ?? ?? ff e1 } 		$a_02_1 = {09 c6 56 81 f9 ?? ?? 00 00 74 1d 8b 03 8d 5b 04 83 e8 ?? 31 f8 48 89 c7 89 46 00 83 e9 fc 83 c6 04 b8 ?? ?? ?? ?? ff e0 } 		$a_00_2 = {69 78 78 78 5f 72 6f 5f 65 5f 5f 4d 65 6d 6f 72 79 } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}