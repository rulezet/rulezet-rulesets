rule Rogue_Win32_FakeXPA_2{
	meta:
		description = "Rogue:Win32/FakeXPA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 00 ?? ?? ?? ?? 55 6e 69 6e 73 74 61 6c 6c 00 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 63 65 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}