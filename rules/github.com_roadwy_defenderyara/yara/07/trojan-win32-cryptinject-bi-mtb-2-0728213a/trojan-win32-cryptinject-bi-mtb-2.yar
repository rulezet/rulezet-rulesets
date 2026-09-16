rule Trojan_Win32_CryptInject_BI_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 da 32 c2 d2 fc 80 c2 e0 0f bb d0 80 f2 75 66 35 bd 0d 66 81 fa ce 01 c1 f8 88 32 da c0 e4 8c 12 c0 d3 e8 89 0c 14 f9 8b 07 8d bf 04 00 00 00 e9 } 		$a_01_1 = {f7 da 42 81 f2 81 3a eb 41 d1 ca 66 f7 c1 8c 0b 80 fa 45 33 da f9 03 f2 e9 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}