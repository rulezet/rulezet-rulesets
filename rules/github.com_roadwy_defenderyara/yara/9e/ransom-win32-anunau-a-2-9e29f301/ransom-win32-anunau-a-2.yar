rule Ransom_Win32_Anunau_A_2{
	meta:
		description = "Ransom:Win32/Anunau.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 76 00 69 00 63 00 65 00 49 00 44 00 00 00 00 00 01 00 00 00 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 00 00 44 69 73 61 62 6c 65 52 6f 75 74 69 6e 65 6c 79 54 61 6b 69 6e 67 41 63 74 69 6f 6e 00 00 00 00 53 4f 46 54 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}