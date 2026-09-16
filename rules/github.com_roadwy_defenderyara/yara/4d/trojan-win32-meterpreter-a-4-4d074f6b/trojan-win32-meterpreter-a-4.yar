rule Trojan_Win32_Meterpreter_A__4{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 } 		$a_01_1 = {68 33 32 00 00 68 77 73 32 5f } 		$a_01_2 = {68 58 a4 53 e5 ff d5 } 		$a_01_3 = {68 ea 0f df e0 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}