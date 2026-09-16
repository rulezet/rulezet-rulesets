rule Trojan_Win64_Farfli_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 30 05 48 ff c0 48 ff c9 } 		$a_01_1 = {80 30 05 48 ff c0 49 ff cc } 		$a_01_2 = {47 6c 6f 62 61 6c 5c 44 48 47 47 6c 6f 62 61 6c 4d 75 74 65 78 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}