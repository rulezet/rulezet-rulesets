rule Trojan_Win64_BazarLoader_RPX_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 8b 04 87 43 89 04 8b 41 8d 40 01 41 ff c1 45 33 c0 3b c3 44 0f 45 c0 45 3b ca 72 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}