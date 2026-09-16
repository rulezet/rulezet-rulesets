rule Trojan_Win32_Filecoder_ARA_MTB_6{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 69 67 43 61 73 68 46 6f 72 59 6f 75 2e 65 78 65 } 		$a_01_1 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 6b 6e 6f 77 20 6d 6f 72 65 20 6c 6f 6f 6b 20 61 74 20 74 68 65 20 61 74 74 61 63 68 6d 65 6e 74 21 } 		$a_01_2 = {52 61 6e 73 6f 6d 57 61 72 5f 45 4f 46 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}