rule Backdoor_Win32_Stradatu_3{
	meta:
		description = "Backdoor:Win32/Stradatu,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 2e 33 2e 36 2e 31 2e 35 2e 35 2e 37 2e 33 2e 32 } 		$a_01_1 = {34 2e 31 2e 33 31 31 2e 31 30 2e 33 2e 33 } 		$a_01_2 = {52 45 56 45 52 53 45 53 48 45 4c 4c } 		$a_01_3 = {55 4e 4b 4e 4f 57 20 43 4c 49 45 4e 54 20 54 59 50 45 } 		$a_01_4 = {55 4e 4b 4e 4f 57 20 48 4f 53 54 20 54 59 50 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=7
 
}