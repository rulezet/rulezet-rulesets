rule TrojanSpy_Win32_Banker_AOT{
	meta:
		description = "TrojanSpy:Win32/Banker.AOT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 78 69 6d 75 73 64 65 63 69 6d 75 73 2e 63 70 6c } 		$a_01_1 = {73 65 72 61 73 61 2e 63 6f 6d 2e 62 72 } 		$a_01_2 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 61 76 61 5f 75 70 64 61 74 65 33 32 2e 63 6d 64 } 		$a_01_3 = {30 2e 67 69 66 3f 33 30 37 36 34 35 35 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}