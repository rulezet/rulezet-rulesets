rule Rogue_Win32_InternetAntivirus_5{
	meta:
		description = "Rogue:Win32/InternetAntivirus,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {78 6f 6f 6d 65 72 2e 61 6c 69 63 65 2e 69 74 [0-20] 55 8b ec 33 c0 55 68 ?? ?? 40 00 64 ff 30 64 89 20 } 		$a_00_1 = {49 6e 74 65 72 6e 65 74 20 41 6e 74 69 76 69 72 75 73 20 50 72 6f 22 20 2f 70 61 73 73 77 6f 72 64 3d 61 76 69 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}