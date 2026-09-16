rule TrojanSpy_Win32_Hozets_A{
	meta:
		description = "TrojanSpy:Win32/Hozets.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 66 7a 2e 65 78 65 } 		$a_01_1 = {31 30 2e 31 2e 32 35 31 2e 31 32 35 20 68 79 6d 68 74 2e 68 37 34 2e 31 73 74 78 79 2e 6e 65 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}