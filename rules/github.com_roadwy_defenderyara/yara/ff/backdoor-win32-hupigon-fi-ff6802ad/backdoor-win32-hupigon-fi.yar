rule Backdoor_Win32_Hupigon_FI{
	meta:
		description = "Backdoor:Win32/Hupigon.FI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 52 41 59 70 49 47 45 4f 4e } 		$a_01_1 = {50 4f 73 43 52 45 45 4e 63 45 4e 54 45 52 } 		$a_01_2 = {6f 4e 6b 45 59 64 4f 57 4e } 		$a_01_3 = {61 55 54 6c 4f 47 49 4e 74 63 70 63 4c 49 45 4e 54 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}