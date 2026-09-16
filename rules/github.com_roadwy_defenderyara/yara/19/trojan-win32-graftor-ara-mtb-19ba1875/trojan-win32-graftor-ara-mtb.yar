rule Trojan_Win32_Graftor_ARA_MTB{
	meta:
		description = "Trojan:Win32/Graftor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 5c 04 10 80 f3 1a 88 5c 04 10 40 83 f8 05 72 ef } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}