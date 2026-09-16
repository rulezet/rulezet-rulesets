rule Trojan_Win64_IcedID_EM_MTB_7{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 44 24 38 4f c6 44 24 39 16 e9 44 01 00 00 80 44 24 30 60 c6 44 24 31 39 66 3b d2 74 3b 80 44 24 34 3c c6 44 24 35 12 3a e4 74 56 } 		$a_01_1 = {69 75 61 73 64 75 79 75 61 67 73 64 6a 61 73 61 73 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}