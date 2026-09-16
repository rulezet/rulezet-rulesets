rule Trojan_Win32_AsyncRat_MA_MTB_3{
	meta:
		description = "Trojan:Win32/AsyncRat.MA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {d2 7f 14 a7 2b cb e4 46 bf 9c 22 d7 55 22 0e df } 		$a_01_1 = {94 ca c5 e4 95 b9 a1 40 9a c2 32 36 1a 7d 96 0f 01 } 		$a_01_2 = {82 8c 30 ab 9c ca 96 93 19 b6 34 10 a4 89 6c 44 a1 3e fb 30 ad a4 ad af } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}