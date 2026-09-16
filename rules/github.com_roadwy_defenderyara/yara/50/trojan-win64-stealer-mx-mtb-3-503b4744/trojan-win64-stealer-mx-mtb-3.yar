rule Trojan_Win64_Stealer_MX_MTB_3{
	meta:
		description = "Trojan:Win64/Stealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 1f 41 8b c0 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 ca 49 33 d0 48 89 15 db 5b 05 00 48 83 c4 28 } 		$a_01_1 = {4f 62 66 75 73 63 61 74 69 6f 6e 20 6c 61 79 65 72 20 61 63 74 69 76 65 20 2d 20 73 79 73 63 61 6c 6c 73 20 65 6e 63 72 79 70 74 65 64 20 69 6e 20 6d 65 6d 6f 72 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}