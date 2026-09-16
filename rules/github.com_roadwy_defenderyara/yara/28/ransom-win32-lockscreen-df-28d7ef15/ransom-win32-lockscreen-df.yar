rule Ransom_Win32_LockScreen_DF{
	meta:
		description = "Ransom:Win32/LockScreen.DF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 6f 6c 69 63 65 [0-05] 52 65 70 6f 72 74 00 } 		$a_01_1 = {3c 6d 3e 50 72 65 73 73 20 45 53 43 20 61 6e 64 20 74 72 79 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 20 74 68 65 20 49 6e 74 65 72 6e 65 74 2e } 		$a_01_2 = {68 2e 70 68 70 68 6d 61 69 6e } 		$a_01_3 = {6c 6f 63 6b 2e 64 6c 6c 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}