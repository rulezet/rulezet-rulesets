rule Trojan_Win32_AsyncRat_MA_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {c4 01 ed f7 db 4a 8e 52 a5 5a 0c 34 13 21 } 		$a_01_1 = {32 2d 41 39 46 43 44 6d 49 67 73 45 66 70 79 63 00 41 31 7d 23 } 		$a_01_2 = {63 68 6b 4c 6f 61 64 54 69 70 73 41 74 53 74 61 72 74 75 70 } 		$a_01_3 = {4d 00 75 00 69 00 75 00 63 00 75 00 72 00 75 00 6f 00 75 00 73 00 75 00 6f 00 75 00 66 00 75 00 74 00 75 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}