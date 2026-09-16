rule Trojan_Win32_Filecoder_ARA_MTB_7{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 74 20 74 68 65 20 6d 6f 6d 65 6e 74 2c 20 79 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 6e 6f 74 20 70 72 6f 74 65 63 74 65 64 2e } 		$a_01_1 = {54 6f 20 67 65 74 20 73 74 61 72 74 65 64 2c 20 73 65 6e 64 20 61 20 66 69 6c 65 20 74 6f 20 64 65 63 72 79 70 74 20 74 72 69 61 6c 2e } 		$a_80_2 = {74 43 72 79 70 74 6f 50 50 20 52 4e 47 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}