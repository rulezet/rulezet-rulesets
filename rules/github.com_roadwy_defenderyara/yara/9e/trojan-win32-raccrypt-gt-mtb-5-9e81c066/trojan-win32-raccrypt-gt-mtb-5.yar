rule Trojan_Win32_Raccrypt_GT_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5e aa cd 04 c7 [0-05] d2 a3 3a 6a c7 [0-05] 68 3f 01 6b c7 [0-05] 3f 5d 8e 10 c7 [0-05] 5b fd 46 4a c7 [0-05] d7 99 ac 7c c7 [0-05] b5 0d 96 5f c7 [0-05] b3 6b 51 02 c7 [0-05] 65 51 93 0b c7 [0-05] 8b 68 36 7d c7 [0-05] 32 a9 23 7a c7 [0-05] 00 2b 5a 11 c7 [0-05] b9 af 00 62 c7 [0-05] 4e 0b 44 74 c7 [0-05] 12 65 93 01 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}