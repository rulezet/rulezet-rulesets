rule Virus_Win32_Induc_A{
	meta:
		description = "Virus:Win32/Induc.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 72 69 74 65 6c 6e 28 66 32 2c 24 24 24 24 2b 73 63 5b 32 34 5d 2b 24 24 24 } 		$a_03_1 = {bb 01 00 00 00 be ?? ?? ?? ?? 8b 16 8b c7 e8 ?? ?? ?? ff e8 ?? ?? ?? ff e8 ?? ?? ?? ff 83 c6 04 4b 75 e7 bb 17 00 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}