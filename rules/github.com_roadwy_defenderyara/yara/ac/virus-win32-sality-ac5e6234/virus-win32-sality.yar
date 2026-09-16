rule Virus_Win32_Sality{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_07_0 = {8a 44 05 00 30 07 (80 e9 01|fe c9) 5e 4e 0f 90 03 05 01 84 ?? ?? ?? ?? e9 85 90 16 fe c2 } 	condition:
		((#a_07_0  & 1)*1) >=1
 
}