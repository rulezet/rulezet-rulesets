rule TrojanSpy_Win32_Pterodo_A{
	meta:
		description = "TrojanSpy:Win32/Pterodo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 53 42 67 72 61 62 62 65 72 2e 64 6c 6c 00 53 74 61 72 74 42 61 63 6b 75 70 } 		$a_01_1 = {5f 00 5f 00 57 00 73 00 6e 00 75 00 73 00 62 00 37 00 33 00 5f 00 5f 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}