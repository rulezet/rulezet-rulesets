rule Trojan_Win32_Qakbot_DO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {6e 64 73 33 30 77 52 2e 64 6c 6c } 		$a_01_2 = {4c 41 6c 77 4c 57 49 71 75 6f } 		$a_01_3 = {52 41 64 74 56 4b 68 41 4e 70 } 		$a_01_4 = {58 6b 46 53 4e 4e 6d 70 78 } 		$a_01_5 = {5a 4d 45 70 42 44 58 57 6b 50 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}