rule Trojan_Win32_Copak_BAF_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 10 81 c6 01 00 00 00 88 11 21 f3 43 41 4b 21 f6 81 c0 02 00 00 00 29 de 39 f8 7e } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}