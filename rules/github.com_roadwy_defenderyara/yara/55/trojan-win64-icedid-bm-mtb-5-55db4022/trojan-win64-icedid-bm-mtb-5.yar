rule Trojan_Win64_IcedID_BM_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b f8 eb 2c 48 8d 8c 24 ?? ?? ?? ?? ff 54 24 ?? eb 14 48 8d 84 24 ?? ?? ?? ?? 48 8b f8 eb 20 83 c1 14 f3 a4 eb 31 48 81 c4 ?? ?? ?? ?? 5f eb } 		$a_00_1 = {79 67 75 61 73 64 68 75 61 73 79 64 67 74 61 76 73 79 64 79 61 73 64 61 6b 6a 61 } 		$a_00_2 = {72 71 64 61 6b 63 2e 64 6c 6c } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}