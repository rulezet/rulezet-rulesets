rule Ransom_Win32_FileCoder_M_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 2c e4 09 c5 83 e7 00 31 ef 5d 6a 00 89 14 e4 31 d2 31 fa 89 93 ?? ?? ?? ?? 5a 89 45 fc 2b 45 fc 0b 83 ?? ?? ?? ?? 83 e6 00 31 c6 8b 45 fc 89 7d f8 29 ff 0b bb ?? ?? ?? ?? 89 f9 8b 7d f8 fc f3 a4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}