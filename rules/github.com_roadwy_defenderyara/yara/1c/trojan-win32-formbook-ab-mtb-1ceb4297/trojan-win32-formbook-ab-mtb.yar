rule Trojan_Win32_Formbook_AB_MTB{
	meta:
		description = "Trojan:Win32/Formbook.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 17 8a ca 32 c2 2a c8 80 c1 14 c0 c9 02 32 ca 2a ca f6 d1 32 ca 02 ca f6 d1 80 c1 37 32 ca 88 0c 17 42 3b d3 72 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}