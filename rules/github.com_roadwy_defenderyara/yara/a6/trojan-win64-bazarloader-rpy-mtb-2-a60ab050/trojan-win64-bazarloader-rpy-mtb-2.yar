rule Trojan_Win64_BazarLoader_RPY_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 f6 74 0b 83 fe 01 75 0a 41 01 3c 91 eb 04 41 89 3c 91 41 8d 04 28 41 8b ce 03 f8 23 cd 41 8b c0 48 ff c2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}