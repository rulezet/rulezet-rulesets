rule Trojan_Win64_BazarLoader_RPX_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c2 7f 89 d7 c1 ef 1f c1 fa 06 01 fa 89 d7 c1 e7 07 29 fa 01 f2 83 c2 7f 88 14 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}