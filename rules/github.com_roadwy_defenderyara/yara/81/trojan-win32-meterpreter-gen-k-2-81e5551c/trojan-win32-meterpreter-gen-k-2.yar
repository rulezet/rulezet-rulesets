rule Trojan_Win32_Meterpreter_gen_K_2{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff e0 31 db 64 8b 43 30 8b 40 0c 8b 70 1c ad 8b 68 08 5e 66 53 66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } 		$a_01_1 = {66 b9 e7 df ff d6 66 b9 a8 6f ff d6 } 		$a_01_2 = {66 b9 33 ce ff d6 89 e1 50 b4 0c 50 51 57 51 66 b9 c0 38 ff e6 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}