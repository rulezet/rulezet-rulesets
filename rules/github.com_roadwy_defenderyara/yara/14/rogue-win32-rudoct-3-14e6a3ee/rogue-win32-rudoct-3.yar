rule Rogue_Win32_Rudoct_3{
	meta:
		description = "Rogue:Win32/Rudoct,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 43 44 65 66 65 6e 64 65 72 53 69 6c 65 6e 74 53 65 74 75 70 2e 6d 73 69 22 0d 0a 66 69 6c 65 5f 54 6f 5f 44 6f 6e 77 6c 6f 61 64 20 3d 20 22 22 20 26 20 72 6e 64 53 74 72 20 26 20 22 2e 6d 73 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}