rule Backdoor_Win64_Bazarldr_MK_MTB_2{
	meta:
		description = "Backdoor:Win64/Bazarldr.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 20 44 8b cb 44 8b c0 33 c9 ff 15 [0-04] 48 8b d8 44 8b 44 24 [0-01] 48 8b d7 48 8b c8 e8 [0-03] 00 } 		$a_03_1 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-01] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4 } 		$a_03_2 = {41 0f b6 00 48 ff c1 49 ff c8 48 3b cb 42 88 44 21 [0-01] 7c ec } 		$a_03_3 = {8b 06 48 8b 4c 24 [0-01] 45 33 c9 89 44 24 [0-01] 45 8d 41 [0-01] 33 d2 48 89 74 24 [0-01] 48 89 6c 24 [0-01] ff 15 [0-04] 85 c0 0f 95 c0 eb bd } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}