rule Trojan_Win64_BazarLoader_RPY_MTB_3{
	meta:
		description = "Trojan:Win64/BazarLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cd 03 d8 23 ce 41 8b c0 48 ff c2 0b c3 03 f0 41 8b c0 03 f1 33 c6 ff c0 03 e8 8b c6 33 c3 8b cd 44 03 c0 33 ce 44 03 c1 49 3b d2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}