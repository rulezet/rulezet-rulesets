rule TrojanSpy_Win32_SocStealer_C{
	meta:
		description = "TrojanSpy:Win32/SocStealer.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 7b 00 36 00 44 00 31 00 38 00 37 00 43 00 43 00 38 00 2d 00 33 00 35 00 42 00 44 00 2d 00 34 00 37 00 46 00 36 00 2d 00 38 00 37 00 36 00 30 00 2d 00 44 00 34 00 30 00 36 00 41 00 41 00 31 00 39 00 32 00 37 00 42 00 31 00 7d 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}