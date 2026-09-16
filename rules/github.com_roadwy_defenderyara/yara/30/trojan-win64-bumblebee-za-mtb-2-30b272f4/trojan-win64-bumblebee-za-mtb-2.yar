rule Trojan_Win64_BumbleBee_ZA_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.ZA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 a0 be a2 b6 7d 46 5d 95 4f 2e d5 ed 95 50 de b6 df dc 05 8a e5 95 cd d5 62 32 ec 19 80 be e8 d7 ba ce 96 38 c7 33 7d 83 4c f1 a5 b9 bb cb b5 35 8d d3 39 15 55 9d 94 c2 86 fb 1f 13 a1 77 28 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}