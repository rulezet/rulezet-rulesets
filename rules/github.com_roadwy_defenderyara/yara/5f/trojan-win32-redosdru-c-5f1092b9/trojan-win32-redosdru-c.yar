rule Trojan_Win32_Redosdru_C{
	meta:
		description = "Trojan:Win32/Redosdru.C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 04 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1 } 		$a_01_1 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 } 		$a_02_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d [0-08] 2e 65 78 65 } 		$a_00_3 = {71 6d 67 72 2e 64 6c 6c 00 5c 44 72 69 76 65 72 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}