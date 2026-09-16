rule Virus_Win32_Sality_2{
	meta:
		description = "Virus:Win32/Sality,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b dd 33 c9 66 69 c1 ?? ?? d1 e9 2b c1 d1 e1 66 31 84 0d ?? ?? 00 00 41 41 3b ca 74 02 eb e5 8b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}