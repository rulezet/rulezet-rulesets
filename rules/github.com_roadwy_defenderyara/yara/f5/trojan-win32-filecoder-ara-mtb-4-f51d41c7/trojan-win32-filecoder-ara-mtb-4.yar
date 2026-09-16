rule Trojan_Win32_Filecoder_ARA_MTB_4{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 46 43 56 64 44 6f 64 44 65 69 57 78 4c 44 4e 44 58 } 		$a_80_1 = {52 45 43 4f 56 45 52 } 		$a_80_2 = {64 6f 6c 6c 61 72 73 20 69 6e 20 42 69 74 63 6f 69 6e } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}