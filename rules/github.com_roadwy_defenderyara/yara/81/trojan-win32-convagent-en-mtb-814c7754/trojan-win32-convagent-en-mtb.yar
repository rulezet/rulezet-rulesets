rule Trojan_Win32_Convagent_EN_MTB{
	meta:
		description = "Trojan:Win32/Convagent.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 65 6c 78 73 79 75 31 21 } 		$a_01_1 = {53 48 65 3b 21 } 		$a_01_2 = {44 6f 65 73 20 69 74 20 77 6f 72 6b 21 4c } 		$a_01_3 = {59 48 55 41 73 67 79 75 } 		$a_01_4 = {57 6b 75 78 7a 67 73 58 7b 74 7b 6a 67 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}