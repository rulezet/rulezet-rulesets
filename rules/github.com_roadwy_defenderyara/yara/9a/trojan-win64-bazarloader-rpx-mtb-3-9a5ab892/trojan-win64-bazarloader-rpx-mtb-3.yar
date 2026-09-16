rule Trojan_Win64_BazarLoader_RPX_MTB_3{
	meta:
		description = "Trojan:Win64/BazarLoader.RPX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 0c 01 41 32 0c 3e 88 0c 38 89 f9 83 e1 1f 42 0f b6 14 01 41 32 14 3e 88 14 38 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}