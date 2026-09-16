rule Trojan_Win32_Emotet_DA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {89 44 24 20 b8 02 00 00 00 2b c6 89 6c 24 14 2b c1 8d 6a fd 0f af c6 0f af ef 0f af d9 03 c5 8b 6c 24 34 83 c4 04 8d 04 40 2b c3 2b c2 } 		$a_01_1 = {7a 64 71 31 31 28 7a 74 67 59 45 7a 5f 42 4e 78 57 78 3c 68 57 4f 72 4e 41 42 34 56 34 63 73 75 50 48 42 67 33 76 79 } 	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*3) >=13
 
}