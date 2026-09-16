rule Trojan_Win32_Zusy_KK_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } 		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } 		$a_01_2 = {24 32 64 63 31 63 33 62 38 2d 34 31 33 31 2d 34 37 35 35 2d 61 34 36 36 2d 39 61 30 65 63 64 34 65 34 34 65 38 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3) >=28
 
}