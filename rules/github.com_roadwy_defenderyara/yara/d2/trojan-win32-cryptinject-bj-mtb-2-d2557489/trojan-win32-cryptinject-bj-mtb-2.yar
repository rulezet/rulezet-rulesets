rule Trojan_Win32_CryptInject_BJ_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BJ!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 51 52 56 57 39 } 		$a_01_1 = {50 51 52 56 57 3d 77 } 		$a_01_2 = {50 51 52 56 57 3b 4d } 		$a_01_3 = {50 51 52 56 57 3b 45 } 		$a_01_4 = {50 51 52 56 57 3b 75 } 		$a_01_5 = {77 69 6e 73 70 6f 6f 6c 2e 64 72 76 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}