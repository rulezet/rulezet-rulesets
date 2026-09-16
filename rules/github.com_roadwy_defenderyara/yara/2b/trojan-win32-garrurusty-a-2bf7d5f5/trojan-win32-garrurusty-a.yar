rule Trojan_Win32_Garrurusty_A{
	meta:
		description = "Trojan:Win32/Garrurusty.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c1 be 03 00 00 00 99 f7 fe 8a 04 29 80 c2 41 32 c2 88 04 29 41 3b cb 72 e6 } 		$a_01_1 = {44 00 72 00 57 00 61 00 74 00 73 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } 		$a_01_2 = {44 00 72 00 57 00 61 00 74 00 73 00 6f 00 6e 00 2e 00 63 00 66 00 67 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}