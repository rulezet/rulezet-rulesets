rule Trojan_Win64_Zusy_MR_MTB{
	meta:
		description = "Trojan:Win64/Zusy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 01 48 8d 49 01 ff c0 3b c7 7c } 		$a_01_1 = {44 8b c0 b8 4f ec c4 4e 41 f7 e8 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 1a 44 2b c1 49 63 c0 0f b6 04 38 88 44 1c 30 48 ff c3 48 83 fb 08 } 		$a_01_2 = {45 79 65 4c 6f 76 65 4d 79 4d 75 74 65 58 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*30+(#a_01_2  & 1)*10) >=50
 
}