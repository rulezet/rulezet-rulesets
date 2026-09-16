rule Trojan_Win64_MagniSyscall_A_2{
	meta:
		description = "Trojan:Win64/MagniSyscall.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {4c 8b d1 b8 [0-08] 66 c7 ?? ?? 0f 05 c6 ?? ?? c3 48 c7 ?? ?? 0b 00 00 00 c7 [0-04] 10 00 00 e8 } 		$a_03_1 = {b9 b5 6f 4d 32 e8 ?? ?? ?? ?? 48 8b 4d ?? 33 d2 ff d0 } 		$a_01_2 = {b9 3e 80 3c 9a e8 } 		$a_03_3 = {e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? ?? 00 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}