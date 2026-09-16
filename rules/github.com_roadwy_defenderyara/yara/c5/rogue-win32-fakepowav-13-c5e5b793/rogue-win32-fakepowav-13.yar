rule Rogue_Win32_FakePowav_13{
	meta:
		description = "Rogue:Win32/FakePowav,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 47 48 65 6c 70 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } 		$a_01_1 = {59 47 48 65 6c 70 65 72 2e 53 65 61 72 63 68 48 65 6c 70 65 72 } 		$a_01_2 = {31 46 32 44 39 43 34 37 2d 36 41 43 39 2d 34 38 37 32 2d 41 41 43 43 2d 45 31 43 44 34 39 34 46 30 34 30 43 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}