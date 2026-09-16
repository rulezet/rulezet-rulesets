rule Trojan_Win32_Cobaltstrike_DF_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4b 04 8b c9 8b c7 8b 55 0c 8b c0 c1 e1 02 2b c1 8a 04 10 32 06 88 04 3a 8b c9 8b c7 8b 4b 04 c1 e1 02 8b c9 2b c1 8a 44 10 01 8b c0 32 46 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}