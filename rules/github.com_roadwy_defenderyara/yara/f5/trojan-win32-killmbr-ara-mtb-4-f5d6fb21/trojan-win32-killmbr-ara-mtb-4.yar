rule Trojan_Win32_KillMBR_ARA_MTB_4{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 6f 6f 74 6c 6f 61 64 65 72 3a 20 53 75 63 63 65 73 66 75 6c 6c 79 20 6c 6f 61 64 65 64 } 		$a_01_1 = {4d 65 6d 6f 72 79 20 72 65 67 69 6f 6e 3a 20 30 78 38 30 30 30 20 68 61 73 20 62 65 65 6e 20 6c 6f 61 64 65 64 2e 22 2c 31 33 2c 31 30 2c 31 33 2c 31 30 2c } 		$a_01_2 = {52 65 73 65 74 20 64 69 73 6b 20 73 79 73 74 65 6d } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}