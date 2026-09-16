rule Ransom_Win32_Loktrom_B_4{
	meta:
		description = "Ransom:Win32/Loktrom.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 43 3a 5c 57 49 4e 44 ce 57 53 5c e5 f5 f0 6c ee 72 e5 72 2e 65 78 65 00 } 		$a_01_1 = {00 4c 6f 6b 6f 4d 6f 54 4f 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}