rule Trojan_Win32_Qakbot_MC_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 6a 61 75 7a 79 4f } 		$a_01_1 = {57 44 67 76 51 49 39 34 37 50 4e 37 } 		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_3 = {44 6c 6c 49 6e 73 74 61 6c 6c } 		$a_01_4 = {6e 64 75 6b 74 70 65 37 30 39 62 66 35 35 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}