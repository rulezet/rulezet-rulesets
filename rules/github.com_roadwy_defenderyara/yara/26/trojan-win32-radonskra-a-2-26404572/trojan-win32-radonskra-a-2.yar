rule Trojan_Win32_Radonskra_A_2{
	meta:
		description = "Trojan:Win32/Radonskra.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 64 65 6c 65 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 53 63 72 69 70 74 20 2f 66 } 		$a_01_1 = {2f 63 72 65 61 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 53 63 72 69 70 74 20 2f 74 72 20 22 44 57 56 41 4c 55 45 22 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 66 } 		$a_01_2 = {70 6f 70 2e 6f 6b 69 6e 6f 66 69 6c 6d 2e 72 75 2f 72 75 2e 70 68 70 3f 73 6e 69 64 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}