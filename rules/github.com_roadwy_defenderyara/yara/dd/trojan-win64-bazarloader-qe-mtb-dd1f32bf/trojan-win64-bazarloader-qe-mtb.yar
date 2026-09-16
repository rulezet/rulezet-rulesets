rule Trojan_Win64_BazarLoader_QE_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 37 41 88 c1 41 28 c9 88 c1 80 e9 01 41 00 c9 44 28 c8 88 44 24 37 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}