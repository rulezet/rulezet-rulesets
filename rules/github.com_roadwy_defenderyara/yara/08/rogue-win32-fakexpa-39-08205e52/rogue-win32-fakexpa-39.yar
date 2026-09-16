rule Rogue_Win32_FakeXPA_39{
	meta:
		description = "Rogue:Win32/FakeXPA,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 77 69 6c 6c 20 64 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 69 6e 73 74 61 6c 6c 20 58 50 20 41 6e 74 69 76 69 72 75 73 20 6f 6e 20 79 6f 75 72 20 50 43 2e } 	condition:
		((#a_01_0  & 1)*11) >=11
 
}