rule Trojan_Win64_BazarLoader_AV_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.AV!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 83 ec 20 48 63 41 3c 8b fa 4c 8b d9 8b 9c 08 88 00 00 00 8b ac 08 8c 00 00 00 48 03 d9 8b c2 c1 e8 10 66 85 c0 75 08 0f b7 c7 2b 43 10 eb 72 44 8b 43 20 45 33 c9 44 8b 53 24 4d 03 c3 8b 73 18 4d 03 d3 85 f6 74 3f } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}