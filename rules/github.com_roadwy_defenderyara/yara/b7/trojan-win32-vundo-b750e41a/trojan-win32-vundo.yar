rule Trojan_Win32_Vundo{
	meta:
		description = "Trojan:Win32/Vundo,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 40 42 0f 00 6a 00 ff 15 } 		$a_01_1 = {68 00 14 01 00 68 c8 43 40 00 50 } 		$a_00_2 = {c1 ea 0b 83 e2 03 8b c3 c1 e8 05 8b cb c1 e1 04 33 c1 8b 4c 95 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}