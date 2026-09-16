rule Trojan_Win32_Meterpreter_L_2{
	meta:
		description = "Trojan:Win32/Meterpreter.L,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {8a 02 c1 c9 0d 3c 61 0f b6 c0 72 03 83 c1 e0 03 c8 81 c7 ff ff 00 00 42 66 85 ff 75 e3 81 f9 5b bc 4a 6a 0f 85 } 		$a_03_1 = {8e 4e 0e ec 74 ?? 81 ?? aa fc 0d 7c 74 ?? 81 ?? 54 ca af 91 74 ?? 81 ?? f2 32 f6 0e } 		$a_01_2 = {f0 b5 a2 56 } 		$a_01_3 = {fe 0e 32 ea 75 } 		$a_01_4 = {6d 69 6d 69 6b 61 74 7a 5f 63 75 73 74 6f 6d 5f 63 6f 6d 6d 61 6e 64 } 		$a_01_5 = {5c 00 5c 00 2e 00 5c 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } 		$a_01_6 = {4b 00 69 00 77 00 69 00 41 00 6e 00 64 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 54 00 6f 00 6f 00 6c 00 73 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}