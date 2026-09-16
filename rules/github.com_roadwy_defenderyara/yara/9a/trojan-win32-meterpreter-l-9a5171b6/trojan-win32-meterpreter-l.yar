rule Trojan_Win32_Meterpreter_L{
	meta:
		description = "Trojan:Win32/Meterpreter.L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e } 		$a_01_1 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 } 		$a_01_2 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 } 		$a_01_3 = {f0 b5 a2 56 } 		$a_01_4 = {77 65 62 63 61 6d 5f 61 75 64 69 6f 5f 72 65 63 6f 72 64 } 		$a_01_5 = {25 54 45 4d 50 25 5c 68 6f 6f 6b 2e 64 6c 6c } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}