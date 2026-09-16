rule Trojan_Win64_IcedID_SD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 7c 41 b9 04 00 00 00 41 b8 00 30 00 00 8b d0 33 c9 ff 94 24 } 		$a_03_1 = {48 8b c1 0f b6 44 04 ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}