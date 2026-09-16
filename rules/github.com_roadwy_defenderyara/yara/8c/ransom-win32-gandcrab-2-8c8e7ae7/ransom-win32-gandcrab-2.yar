rule Ransom_Win32_GandCrab_2{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {e8 a7 ff ff ff 30 04 37 6a 00 ff 15 ?? ?? 41 00 8d 85 fc f7 ff ff 50 6a 00 ff 15 ?? ?? 41 00 46 3b 75 08 7c cd 90 09 0e 00 6a 00 ff 15 ?? ?? 41 00 ff 15 ?? ?? 41 00 } 		$a_02_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? 41 00 c1 e8 10 25 ff 7f 00 00 c3 90 09 05 00 a1 ?? ?? 41 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}