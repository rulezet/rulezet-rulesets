rule Trojan_Win32_Filecoder_ARA_MTB_5{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 52 52 61 6e 73 6f 6d } 		$a_01_1 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 65 72 2e 63 6f 6d 2f } 		$a_80_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 53 79 73 74 65 6d 52 65 73 74 6f 72 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}