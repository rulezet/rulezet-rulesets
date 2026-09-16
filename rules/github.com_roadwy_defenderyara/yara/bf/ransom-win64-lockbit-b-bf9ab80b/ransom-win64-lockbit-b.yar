rule Ransom_Win64_LockBit_B{
	meta:
		description = "Ransom:Win64/LockBit.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {31 2e 21 54 } 		$a_01_1 = {99 b5 5b 9b } 		$a_01_2 = {09 a6 52 d2 } 		$a_01_3 = {cc bf 63 aa } 		$a_01_4 = {1d aa a3 3c } 		$a_01_5 = {5b 8d 47 89 } 		$a_01_6 = {c5 0f 95 bc } 		$a_01_7 = {23 32 a1 6f } 		$a_01_8 = {58 70 53 69 6d 75 6c 61 74 65 50 61 72 61 6e 6f 69 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}