rule Trojan_Win32_Farfli_ASDF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f6 8b 45 04 0f b6 04 10 30 04 0b 83 c1 01 39 cf 75 } 		$a_01_1 = {83 ec 08 c7 04 24 e0 2e 00 00 ff 15 } 		$a_01_2 = {66 75 63 6b 79 6f 75 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}