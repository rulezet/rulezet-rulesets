rule Ransom_Win64_FileCoder_AB_MTB_3{
	meta:
		description = "Ransom:Win64/FileCoder.AB!MTB,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 56 48 83 ec 20 48 8b f1 4c 8d 35 0d 58 ff ff 8b ea 44 8b d2 83 e5 04 41 81 e2 80 00 00 00 44 8b ca 41 8b f8 41 83 c9 01 f6 c2 40 44 0f 44 ca } 		$a_01_1 = {83 c9 02 41 f6 c1 08 41 0f 44 c9 45 33 c0 81 e1 3b ff ff ff 85 d2 } 		$a_01_2 = {75 10 48 c1 c1 10 66 f7 c1 ff ff 75 01 c3 48 c1 c9 10 } 		$a_01_3 = {4c 8d 35 0d 58 ff ff 8b ea 44 8b d2 83 e5 04 41 81 e2 80 00 00 00 44 8b ca } 		$a_01_4 = {f6 c2 40 44 0f 44 ca 8b 15 ef 57 03 00 41 8b c9 83 c9 02 41 f6 c1 08 41 0f 44 c9 45 33 c0 81 e1 3b ff ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}