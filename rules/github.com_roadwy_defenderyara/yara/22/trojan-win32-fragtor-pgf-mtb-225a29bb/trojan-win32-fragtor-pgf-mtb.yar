rule Trojan_Win32_Fragtor_PGF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.PGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 1e 33 c8 69 c1 ?? ?? ?? ?? 03 c2 89 84 94 2c 01 00 00 42 81 fa 70 02 00 00 72 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}