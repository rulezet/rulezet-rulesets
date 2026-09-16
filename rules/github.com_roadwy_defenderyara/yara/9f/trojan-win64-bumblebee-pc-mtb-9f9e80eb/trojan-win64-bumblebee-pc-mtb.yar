rule Trojan_Win64_BumbleBee_PC_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 53 6b 35 } 		$a_01_1 = {49 65 50 46 6c } 		$a_01_2 = {42 74 48 31 34 69 } 		$a_01_3 = {53 47 42 4e 46 61 30 } 		$a_01_4 = {42 6e 6b 63 51 38 62 42 58 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}