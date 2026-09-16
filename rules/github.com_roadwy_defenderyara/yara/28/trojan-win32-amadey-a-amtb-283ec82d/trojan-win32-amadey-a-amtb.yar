rule Trojan_Win32_Amadey_A_AMTB{
	meta:
		description = "Trojan:Win32/Amadey.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_80_0 = {8b 15 88 1f 42 00 c1 e2 0d 33 15 88 1f 42 00 89 15 88 1f 42 00 a1 88 1f 42 00 c1 e8 11 33 05 88 1f 42 00 a3 88 1f 42 00 8b 0d 88 1f 42 00 c1 e1 05 33 0d 88 1f 42 00 89 0d 88 1f 42 00 a1 88 1f 42 00 8b e5 } 	condition:
		((#a_80_0  & 1)*7) >=7
 
}