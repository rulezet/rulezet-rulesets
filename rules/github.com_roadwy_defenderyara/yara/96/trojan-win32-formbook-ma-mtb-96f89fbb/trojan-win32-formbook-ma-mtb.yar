rule Trojan_Win32_Formbook_MA_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c8 85 c9 74 1c 8b c7 2b c8 bb 05 1a 00 00 8b ff 8a 04 0f 88 07 8d 7f 01 4b 75 } 		$a_01_1 = {57 00 49 00 4f 00 53 00 4f 00 53 00 4f 00 53 00 4f 00 57 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}