rule Ransom_Win32_Robbinhood_B_dha{
	meta:
		description = "Ransom:Win32/Robbinhood.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 42 4e 4c 44 72 76 } 		$a_02_1 = {70 4c 69 73 74 2e 74 78 74 [0-08] 72 6f 62 6e 72 2e 73 79 73 } 		$a_03_2 = {8a 0c 37 80 e9 ?? 88 0c 30 46 3b f5 7c ba } 	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}