rule Trojan_Win32_RedLine_RPQ_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 75 dc 3b f0 73 57 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37 } 		$a_01_1 = {83 c4 0c 28 1c 37 46 8b 45 d8 eb b9 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}