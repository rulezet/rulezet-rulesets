rule Ransom_Win32_Dopplepaymer_A_3{
	meta:
		description = "Ransom:Win32/Dopplepaymer.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {72 00 6a 00 35 00 37 00 63 00 73 00 39 00 64 00 6d 00 61 00 66 00 59 00 4b 00 4e 00 35 00 42 00 71 00 4b 00 38 00 4f 00 6f 00 75 00 44 00 43 00 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}