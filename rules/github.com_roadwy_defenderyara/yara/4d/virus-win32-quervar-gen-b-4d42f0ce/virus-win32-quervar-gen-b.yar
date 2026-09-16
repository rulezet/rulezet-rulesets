rule Virus_Win32_Quervar_gen_B{
	meta:
		description = "Virus:Win32/Quervar.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 2d 2d 2d 71 72 6e 71 79 76 61 72 2d 2d 2d 5d } 		$a_01_1 = {5b 2b 2b 2b 73 63 61 72 66 61 63 65 2b 2b 2b 5d } 		$a_01_2 = {5b 2d 2d 2d 64 65 61 64 6c 69 6e 65 2d 2d 2d 5d } 		$a_03_3 = {03 cb 81 e1 ff 00 00 00 8b 1c 24 8a 1c 13 32 99 ?? ?? ?? ?? 8b 4c 24 04 88 1c 11 42 48 75 ad 59 5a 5f 5e 5b c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*10) >=11
 
}