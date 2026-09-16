rule Trojan_Win32_Adialer_2{
	meta:
		description = "Trojan:Win32/Adialer,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 c4 5c ff ff ff ff 35 ad 47 40 00 e8 7a 07 00 00 68 a0 00 00 00 8d 85 5c ff ff ff 50 e8 fd 06 00 00 c7 85 5c ff ff ff a0 00 00 00 8d 85 5c ff ff ff 50 ff 35 ad 47 40 00 e8 3b 07 00 00 83 f8 06 74 1e 68 e8 03 00 00 e8 de 06 00 00 8d 85 5c ff ff ff 50 ff 35 ad 47 40 00 e8 1a 07 00 00 eb dd 68 90 01 00 00 e8 c0 06 00 00 c9 c3 } 		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } 		$a_01_2 = {52 61 73 44 69 61 6c 41 } 		$a_01_3 = {73 74 72 73 74 72 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}