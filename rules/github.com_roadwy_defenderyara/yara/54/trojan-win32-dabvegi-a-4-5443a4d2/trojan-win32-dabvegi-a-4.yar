rule Trojan_Win32_Dabvegi_A_4{
	meta:
		description = "Trojan:Win32/Dabvegi.A,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 69 6f 6e 46 69 6c 65 } 		$a_01_1 = {52 65 6d 6f 76 65 43 6f 6e 63 6f 72 72 65 6e 74 65 73 } 		$a_01_2 = {2e 00 62 00 61 00 74 00 } 		$a_01_3 = {2d 00 5b 00 38 00 38 00 5d 00 2d 00 } 		$a_01_4 = {21 00 6e 00 75 00 6b 00 6b 00 68 00 6e 00 62 00 41 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=31
 
}