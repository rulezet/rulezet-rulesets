rule Trojan_Win32_Copak_RDA_MTB{
	meta:
		description = "Trojan:Win32/Copak.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 30 43 53 5b 40 81 eb 61 0a f8 a1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}