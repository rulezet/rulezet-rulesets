rule Trojan_Win32_Copak_BAG_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 4a 88 01 09 da 41 4a 89 d2 81 c6 02 00 00 00 4a 81 c2 c8 f8 52 16 ba 36 f0 27 42 39 fe 7e } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}