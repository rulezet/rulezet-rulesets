rule TrojanSpy_Win32_Keylogger{
	meta:
		description = "TrojanSpy:Win32/Keylogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 52 45 43 59 43 4c 45 52 5c 74 65 6d 70 30 31 2e 74 78 74 00 } 		$a_01_1 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00 } 		$a_01_2 = {5b 00 42 00 4b 00 53 00 50 00 5d 00 } 		$a_01_3 = {5b 00 49 00 4e 00 53 00 45 00 52 00 54 00 5d 00 } 		$a_01_4 = {e9 52 02 00 00 83 ff 40 76 1b 83 ff 5b 73 16 6a 14 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}