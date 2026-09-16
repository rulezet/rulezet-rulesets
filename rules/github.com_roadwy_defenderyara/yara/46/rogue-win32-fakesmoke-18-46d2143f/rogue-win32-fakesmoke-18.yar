rule Rogue_Win32_FakeSmoke_18{
	meta:
		description = "Rogue:Win32/FakeSmoke,SIGNATURE_TYPE_PEHSTR,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 25 73 20 53 6f 66 74 77 61 72 65 5c 25 73 2e 65 78 65 00 } 		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 20 25 73 2e 65 78 65 00 } 		$a_01_2 = {31 2e 32 2e 30 2e 36 34 00 } 		$a_01_3 = {32 2e 34 2e 30 2e 37 30 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}