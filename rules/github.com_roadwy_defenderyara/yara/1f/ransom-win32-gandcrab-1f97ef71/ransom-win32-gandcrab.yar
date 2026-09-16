rule Ransom_Win32_GandCrab{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ff 9c 19 00 00 7d 04 6a 00 ff d6 e8 ?? fa ff ff 8b 4c 24 0c 30 04 39 83 ef 01 79 e3 ff 15 90 90 c7 41 00 64 8b 0d 2c 00 00 00 8b 11 5f 5e c7 42 04 01 00 00 00 33 c0 5b 8b e5 5d c2 10 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}