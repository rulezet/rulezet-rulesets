rule Trojan_Win32_BunnyLoader_RPX_MTB{
	meta:
		description = "Trojan:Win32/BunnyLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {42 75 6e 6e 79 4c 6f 61 64 65 72 5f } 		$a_01_1 = {42 6f 74 49 44 3d } 		$a_01_2 = {42 75 6e 6e 79 2f 54 61 73 6b 48 61 6e 64 6c 65 72 2e 70 68 70 } 		$a_01_3 = {52 75 6e 20 53 74 65 61 6c 65 72 } 		$a_01_4 = {45 63 68 6f 65 72 2e 70 68 70 } 		$a_01_5 = {6e 6f 74 65 70 61 64 2e 65 78 65 } 		$a_01_6 = {4a 6f 68 6e 20 44 6f 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}