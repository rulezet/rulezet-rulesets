rule Ransom_Win32_LockScreen_H_3{
	meta:
		description = "Ransom:Win32/LockScreen.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ab ad c1 c8 ?? ab ad c1 (c0|c8) ?? ab ad } 		$a_03_1 = {8b 1c 0a 3b 19 75 ?? 83 ee 04 83 c1 04 83 fe 04 73 ee } 		$a_03_2 = {8b 31 3b 30 75 ?? 83 ea 04 83 c0 04 83 c1 04 83 fa 04 73 ec } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}