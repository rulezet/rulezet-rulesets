rule Rogue_Win32_Defmid_9{
	meta:
		description = "Rogue:Win32/Defmid,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 73 77 2f 6c 2e 70 68 70 3f } 		$a_01_1 = {61 66 66 5f 69 64 } 		$a_01_2 = {4d 61 63 68 69 6e 65 47 75 69 64 00 42 42 30 32 42 37 45 45 2d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}