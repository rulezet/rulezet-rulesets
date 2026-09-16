rule TrojanSpy_Win32_Banker_AOT_2{
	meta:
		description = "TrojanSpy:Win32/Banker.AOT,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b d0 80 c2 bf 80 ea 1a 73 0d 3c 4d 75 07 80 fb 48 75 02 b0 4e } 		$a_01_1 = {63 6d 64 20 2f 6b 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6a 61 76 61 5f 75 70 64 61 74 65 33 32 2e 63 6d 64 00 } 		$a_01_2 = {50 72 6f 6a 65 63 74 36 36 36 00 } 		$a_01_3 = {75 72 6c 3a 20 00 } 		$a_01_4 = {75 72 6c 32 3a 20 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}