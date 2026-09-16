rule Trojan_Win32_Farfli_ASDG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 2b cb 8a 14 01 80 f2 62 88 10 40 4f 75 } 		$a_01_1 = {66 75 63 6b 79 6f 75 } 		$a_01_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 63 76 68 6f 73 74 2e 65 78 65 } 		$a_01_3 = {5b 50 61 75 73 65 20 42 72 65 61 6b 5d } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}