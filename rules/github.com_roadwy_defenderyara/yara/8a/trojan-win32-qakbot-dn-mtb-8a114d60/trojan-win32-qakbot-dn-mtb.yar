rule Trojan_Win32_Qakbot_DN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {71 6a 33 32 77 67 37 6c 48 44 53 2e 64 6c 6c } 		$a_01_2 = {46 72 73 42 5a 44 43 6d 4b } 		$a_01_3 = {53 42 6e 50 4d 57 49 6d } 		$a_01_4 = {54 53 4c 78 66 4a 71 } 		$a_01_5 = {6e 7a 67 43 51 47 52 4c 44 43 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}