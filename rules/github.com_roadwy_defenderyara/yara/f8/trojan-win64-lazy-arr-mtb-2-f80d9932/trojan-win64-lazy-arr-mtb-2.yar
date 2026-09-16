rule Trojan_Win64_Lazy_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_03_0 = {e0 13 00 00 ?? ?? bd 01 40 01 } 		$a_01_1 = {23 00 0b 02 0e 2c 00 b4 10 00 } 		$a_01_2 = {06 5a 1e 01 00 d0 10 00 } 		$a_01_3 = {3c 9b 00 00 00 30 2f 01 00 00 } 		$a_01_4 = {78 bd 00 00 00 d0 2f 01 00 00 } 	condition:
		((#a_03_0  & 1)*12+(#a_01_1  & 1)*8+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=30
 
}