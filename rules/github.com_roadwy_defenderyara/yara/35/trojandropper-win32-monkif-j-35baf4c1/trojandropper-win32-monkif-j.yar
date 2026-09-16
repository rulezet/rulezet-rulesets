rule TrojanDropper_Win32_Monkif_J{
	meta:
		description = "TrojanDropper:Win32/Monkif.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 8b 74 24 0c 2b f7 [0-09] 2a c2 2c ?? [0-07] 42 3b 54 24 10 [0-03] 7c } 		$a_02_1 = {6d 73 30 30 31 2e 74 6d 70 [0-05] 54 68 72 65 61 64 69 6e 67 4d 6f 64 65 6c [0-05] 70 61 72 74 6d 65 6e 74 [0-05] 25 73 25 73 5c 25 73 00 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 } 	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}