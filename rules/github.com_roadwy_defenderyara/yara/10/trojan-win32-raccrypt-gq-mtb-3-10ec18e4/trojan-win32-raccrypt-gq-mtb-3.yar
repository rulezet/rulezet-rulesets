rule Trojan_Win32_Raccrypt_GQ_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f0 2c cb 49 c7 [0-05] b9 61 c2 1b c7 [0-05] 13 f9 47 7a c7 [0-05] 21 47 ef 5f c7 [0-05] a9 4e 9a 0f c7 [0-05] 0c 04 b3 5e } 		$a_02_1 = {a4 94 77 17 c7 [0-05] a3 af d2 0e c7 [0-05] 8f 06 8d 6a c7 [0-05] 5d 9f f4 68 c7 [0-05] 72 83 38 04 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}