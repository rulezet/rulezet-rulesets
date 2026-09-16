rule Trojan_Win32_EmotetCrypt_DF_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 29 d0 8b 54 24 08 88 1c 0a 01 c1 89 4c 24 1c 8b 44 24 18 35 [0-04] 3d [0-04] 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}