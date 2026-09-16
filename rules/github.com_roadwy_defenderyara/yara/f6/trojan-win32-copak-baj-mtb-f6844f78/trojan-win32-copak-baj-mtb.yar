rule Trojan_Win32_Copak_BAJ_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1a 21 f6 88 1f 29 f1 81 c7 01 00 00 00 01 f1 81 c2 02 00 00 00 81 c1 84 ca 43 d3 21 f6 89 f1 39 c2 7e } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}