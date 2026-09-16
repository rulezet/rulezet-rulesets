rule Trojan_Win32_Tedy_ARR_MTB_4{
	meta:
		description = "Trojan:Win32/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {f2 0f 10 44 24 30 b8 ?? ?? ?? ?? f2 0f 10 0d ?? ?? ?? ?? 66 0f 1f 44 ?? ?? f2 0f 59 c2 f2 0f 58 c1 83 e8 } 		$a_01_1 = {f2 0f 59 f0 f2 0f 59 f0 f2 0f 59 f0 83 e8 03 75 ef } 		$a_01_2 = {66 0f 6f c1 66 0f fc c1 66 0f fc c1 66 0f 6f c8 66 0f fc c8 66 0f fc c9 66 0f fc c9 66 0f fc c1 } 	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}