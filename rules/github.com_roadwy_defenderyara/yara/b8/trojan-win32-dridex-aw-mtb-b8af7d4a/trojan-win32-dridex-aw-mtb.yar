rule Trojan_Win32_Dridex_AW_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {b0 4a b1 24 8a 54 24 43 88 44 24 2b 88 d0 f6 e1 8a 4c 24 7f 88 84 24 98 00 00 00 8a 44 24 2b 38 c8 } 		$a_01_1 = {31 d2 ba 14 35 09 00 39 d0 77 2d 83 c0 01 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc } 	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}