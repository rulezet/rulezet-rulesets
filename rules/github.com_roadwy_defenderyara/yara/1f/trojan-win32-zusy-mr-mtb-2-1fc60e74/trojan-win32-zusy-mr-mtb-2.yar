rule Trojan_Win32_Zusy_MR_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 34 41 31 33 30 30 30 30 30 30 30 38 42 34 30 31 30 38 42 34 30 33 43 38 39 34 34 32 34 30 34 43 39 43 33 } 		$a_01_1 = {8d 85 5c ff ff ff 50 8d 85 60 ff ff ff 50 8d 85 64 ff ff ff 50 8d 85 68 ff ff ff 50 8d 85 6c ff ff ff 50 8d 45 c0 50 8b 45 08 8b 00 ff } 		$a_01_2 = {89 45 84 c7 45 a4 02 00 00 00 c7 45 9c 02 00 00 00 c7 45 b4 34 63 40 00 c7 45 ac 08 00 00 00 8d 45 c0 } 		$a_01_3 = {8b 45 e4 8b 00 99 2b c2 d1 f8 8b 55 c8 88 0c 02 8d 45 a8 50 8d 45 ac 50 6a 02 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*25) >=55
 
}