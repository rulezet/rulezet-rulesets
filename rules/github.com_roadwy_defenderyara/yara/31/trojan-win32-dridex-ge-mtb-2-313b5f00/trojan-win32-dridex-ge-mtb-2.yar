rule Trojan_Win32_Dridex_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d8 8b fe 83 c9 ff 33 c0 83 c4 04 f2 ae f7 d1 2b f9 8b d1 8b f7 8b fb c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 33 f6 85 ed 76 20 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 46 69 6c 65 41 70 69 2e 67 79 61 6f 74 74 2e 74 6f 70 2f 30 30 31 2f 70 75 70 70 65 74 2e 54 78 74 } 		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}