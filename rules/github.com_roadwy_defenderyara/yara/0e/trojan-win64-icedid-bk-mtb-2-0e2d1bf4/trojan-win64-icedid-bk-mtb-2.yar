rule Trojan_Win64_IcedID_BK_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ec c1 fa 04 8b c2 c1 e8 1f 03 d0 49 63 c4 41 83 c4 01 48 63 ca 48 6b c9 35 48 03 c8 48 8b 44 24 28 42 0f b6 8c 31 [0-04] 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 } 		$a_01_1 = {36 3e 3e 72 73 45 45 6f 59 43 58 6b 32 24 4d 72 49 4c 73 76 52 24 57 51 79 54 55 36 46 6c 35 52 56 67 67 54 57 65 68 71 3e 23 53 31 } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}