rule Ransom_Win32_Rolsig_A{
	meta:
		description = "Ransom:Win32/Rolsig.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 8b c3 43 8b ca 83 e0 01 8b c2 75 0b c1 e1 05 d1 e8 33 c8 33 ce eb 0c c1 e1 09 c1 e8 03 33 c8 33 ce f7 d1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}