rule Trojan_Win64_IcedId_FA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedId.FA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8a 09 4d 8d 49 02 88 4c 24 30 8a 4c 24 30 83 e9 25 88 4c 24 30 8a 44 24 30 c0 e0 04 88 44 24 30 8a 44 24 30 88 44 24 38 41 8a 41 ff 88 44 24 30 8a 44 24 30 83 e8 38 88 44 24 30 0f b6 44 24 38 8a 4c 24 30 0b c8 88 4c 24 38 0f b6 44 24 38 8a 4c 24 40 33 c8 88 4c 24 38 8a 44 24 40 fe c0 88 44 24 40 8a 44 24 38 41 88 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}