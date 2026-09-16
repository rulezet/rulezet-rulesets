rule Trojan_Win32_Farfli_RPX_MTB_7{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 2c 4b c6 44 24 2e 52 c6 44 24 2f 4e c6 44 24 31 4c c6 44 24 32 33 c6 44 24 33 32 c6 44 24 34 2e c6 44 24 35 64 c6 44 24 38 00 c6 44 24 1c 56 c6 44 24 1d 69 c6 44 24 1e 72 c6 44 24 1f 74 c6 44 24 20 75 c6 44 24 21 61 c6 44 24 23 41 c6 44 24 26 6f c6 44 24 27 63 c6 44 24 28 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}