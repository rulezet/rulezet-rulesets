rule Trojan_Win32_Qakbot_EA_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {54 4f 63 53 63 39 38 39 38 4d } 		$a_01_2 = {54 52 6f 4d 71 56 43 37 72 } 		$a_01_3 = {55 44 4f 79 73 52 } 		$a_01_4 = {57 58 62 62 61 32 39 38 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}