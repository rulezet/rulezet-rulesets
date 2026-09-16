rule Trojan_Win32_FusionBlaze_C_dha_2{
	meta:
		description = "Trojan:Win32/FusionBlaze.C!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 69 6e 6a 65 63 74 50 45 5d 20 73 76 63 4e 61 6d 65 3d 25 73 20 6d 6f 64 75 6c 65 50 61 74 68 3d 25 73 7c 20 70 69 64 3d 25 64 20 74 69 64 3d 25 64 20 68 4d 6f 64 75 6c 65 3d 30 78 25 70 20 65 6e 74 72 79 3d 30 78 25 70 } 		$a_01_1 = {25 73 3a 25 64 3a 25 73 3a 25 64 3a 25 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}