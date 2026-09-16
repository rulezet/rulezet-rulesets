rule Rogue_Win32_InternetAntivirus_16{
	meta:
		description = "Rogue:Win32/InternetAntivirus,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 90 66 8d 52 00 57 90 66 8d 52 00 89 34 24 90 66 8d 52 00 6a 30 e9 cc 02 00 00 54 e9 cc 02 00 00 57 90 66 8d 52 00 57 90 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}