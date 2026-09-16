rule Backdoor_Win32_Kriskynote_A{
	meta:
		description = "Backdoor:Win32/Kriskynote.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 66 0f 1f 84 00 00 00 00 00 40 30 3b 48 ff c3 40 fe c7 48 ff c9 75 f2 48 8b cd ff 15 } 		$a_01_1 = {41 0f b6 0b ff c3 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff } 		$a_01_2 = {49 6e 73 74 61 6c 6c 5f 75 61 63 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}