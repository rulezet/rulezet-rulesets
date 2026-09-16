rule Trojan_Win64_Dridex_EM_MTB{
	meta:
		description = "Trojan:Win64/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 34 89 ca 83 e2 1f 41 89 c8 45 89 c1 89 d2 41 89 d2 4c 8b 5c 24 18 43 8a 1c 0b 42 2a 1c 10 48 8b 44 24 08 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}