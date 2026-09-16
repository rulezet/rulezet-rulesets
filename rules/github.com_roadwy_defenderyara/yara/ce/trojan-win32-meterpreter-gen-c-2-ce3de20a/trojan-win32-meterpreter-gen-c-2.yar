rule Trojan_Win32_Meterpreter_gen_C_2{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {b9 c2 eb 38 5f 48 89 c6 e8 ?? ?? ?? ?? b9 ea 0f df e0 48 89 c5 e8 } 		$a_01_1 = {48 b8 77 73 32 5f 33 32 2e 64 } 		$a_01_2 = {b9 99 a5 74 61 e8 } 		$a_03_3 = {b9 02 d9 c8 5f [0-04] e8 } 		$a_01_4 = {b9 58 a4 53 e5 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}