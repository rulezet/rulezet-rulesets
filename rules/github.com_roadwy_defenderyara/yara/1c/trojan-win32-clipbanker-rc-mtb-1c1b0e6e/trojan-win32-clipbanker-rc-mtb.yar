rule Trojan_Win32_ClipBanker_RC_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 4e 66 75 59 55 38 6d 54 67 73 4d 56 4c 45 56 57 51 4a 6d 4c 6a 45 50 6d 57 35 4e 68 73 46 77 66 46 } 		$a_01_1 = {30 78 36 33 44 30 36 34 63 42 63 36 65 35 32 39 35 31 64 65 35 33 37 33 35 32 32 37 38 46 32 62 44 35 35 36 41 31 32 33 35 43 } 		$a_01_2 = {88 b6 5c e5 9f ba e7 a1 80 e5 8a 9f e8 83 bd 5c } 		$a_01_3 = {52 65 6c 65 61 73 65 5c 43 6c 69 70 70 65 72 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}