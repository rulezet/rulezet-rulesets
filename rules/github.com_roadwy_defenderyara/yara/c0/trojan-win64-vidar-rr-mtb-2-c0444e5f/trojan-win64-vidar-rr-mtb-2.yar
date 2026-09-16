rule Trojan_Win64_Vidar_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Vidar.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 69 04 24 41 42 0f 00 49 f7 e6 48 c1 ea 12 48 ff c2 49 89 14 24 0f 31 48 c1 e2 20 48 09 c2 49 31 55 00 49 8b 45 00 48 c1 e0 07 49 8b 55 00 48 c1 ea 0b 48 31 c2 49 89 55 00 49 8b 04 24 49 01 45 00 49 8b 04 24 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}