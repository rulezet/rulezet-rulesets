rule Rogue_Win32_FakeXPA{
	meta:
		description = "Rogue:Win32/FakeXPA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 6f 74 6f 48 65 6c 6c 31 32 33 31 32 33 5f 5f 00 00 00 00 53 68 69 74 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}