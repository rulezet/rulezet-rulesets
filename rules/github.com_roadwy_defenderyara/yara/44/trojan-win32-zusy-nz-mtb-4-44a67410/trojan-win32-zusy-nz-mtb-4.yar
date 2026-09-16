rule Trojan_Win32_Zusy_NZ_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 3f 23 75 f2 8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 50 5f 00 } 		$a_01_1 = {83 c7 04 83 e9 04 77 f1 01 cf e9 2c ff ff ff 5e 89 f7 b9 d0 ac 00 00 8a 07 47 2c e8 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}