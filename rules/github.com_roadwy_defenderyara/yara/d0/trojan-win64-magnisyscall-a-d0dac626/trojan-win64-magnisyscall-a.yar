rule Trojan_Win64_MagniSyscall_A{
	meta:
		description = "Trojan:Win64/MagniSyscall.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 33 c0 4c 8b d1 b8 18 00 00 00 0f 05 c3 e9 [0-20] 56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 } 		$a_01_1 = {b9 fe 60 39 5b e8 } 		$a_01_2 = {b9 3e 80 3c 9a e8 } 		$a_03_3 = {e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? ?? 00 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}