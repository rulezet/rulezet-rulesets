rule Trojan_Win32_Fragtor_ARR_MTB_5{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cb 8d 55 d4 2b c8 be ?? ?? ?? ?? 3b ce 0f 42 f1 83 7d } 		$a_81_1 = {30 4a 65 77 66 33 33 34 77 65 72 66 35 32 44 4b 34 38 39 53 45 56 35 36 37 45 46 47 46 44 47 77 59 5a 73 64 66 65 57 52 74 4e 64 31 32 33 41 42 43 65 75 76 77 7a } 	condition:
		((#a_03_0  & 1)*18+(#a_81_1  & 1)*2) >=20
 
}