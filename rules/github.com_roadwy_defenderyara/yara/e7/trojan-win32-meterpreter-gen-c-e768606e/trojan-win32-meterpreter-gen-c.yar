rule Trojan_Win32_Meterpreter_gen_C{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 } 		$a_01_1 = {68 33 32 00 00 68 77 73 32 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}