rule Trojan_Win32_FileCoder_NF_MTB_3{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {a1 8c 26 43 00 42 8a 44 10 ff 88 44 17 ff 8b 0d 88 26 43 00 8b 3d 90 26 43 00 3b d1 7c e2 a1 84 26 43 00 } 		$a_01_1 = {8b 3d 90 26 43 00 33 d2 f7 f1 8a 4c 37 ff 8a 04 17 88 0c 17 8b 0d 90 26 43 00 88 44 31 ff a1 84 26 43 00 8b 3d 14 26 43 00 8b c8 c1 e9 19 c1 e0 07 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}