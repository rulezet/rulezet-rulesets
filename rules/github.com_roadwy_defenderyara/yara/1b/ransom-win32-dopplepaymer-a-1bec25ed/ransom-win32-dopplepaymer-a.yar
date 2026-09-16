rule Ransom_Win32_Dopplepaymer_A{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {23 00 68 00 65 00 72 00 6a 00 57 00 52 00 4a 00 40 00 33 00 34 00 79 00 68 00 65 00 72 00 6a 00 65 00 72 00 } 		$a_00_1 = {41 73 73 6f 63 49 73 44 61 6e 67 65 72 6f 75 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}