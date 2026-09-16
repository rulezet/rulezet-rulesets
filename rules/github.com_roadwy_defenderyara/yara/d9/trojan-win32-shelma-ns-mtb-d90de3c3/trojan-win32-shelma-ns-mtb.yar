rule Trojan_Win32_Shelma_NS_MTB{
	meta:
		description = "Trojan:Win32/Shelma.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 4d e8 64 a3 00 00 00 00 8b 1e 6a 18 e8 ?? ?? ?? ?? 83 c4 04 8d 78 10 8b 4d 0c f2 0f 10 01 } 		$a_01_1 = {69 64 65 6e 74 69 66 69 65 72 20 72 65 6d 6f 76 65 64 } 		$a_01_2 = {68 6f 73 74 20 75 6e 72 65 61 63 68 61 62 6c 65 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}