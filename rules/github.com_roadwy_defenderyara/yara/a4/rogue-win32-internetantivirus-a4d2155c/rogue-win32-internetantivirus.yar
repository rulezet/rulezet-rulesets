rule Rogue_Win32_InternetAntivirus{
	meta:
		description = "Rogue:Win32/InternetAntivirus,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 67 75 61 72 64 2e 69 6e 69 00 00 ff ff ff ff 08 00 00 00 45 78 74 65 72 6e 61 6c 00 00 00 00 ff ff ff ff 05 00 00 00 47 75 61 72 64 00 00 00 ff ff ff ff 07 00 00 00 50 48 61 6e 64 6c 65 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}