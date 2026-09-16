rule Trojan_Win64_Tedy_ARR_MTB_6{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f be 51 ?? 01 d0 41 31 c0 4c 39 c9 } 		$a_01_1 = {4e 35 7a 68 61 6e 67 31 32 65 6e 63 79 70 74 69 6f 6e 41 6c 67 49 4c 79 36 34 45 45 45 } 		$a_01_2 = {4e 35 7a 68 61 6e 67 31 33 64 65 73 45 6e 63 72 79 70 74 69 6f 6e 45 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*8+(#a_01_2  & 1)*10) >=20
 
}