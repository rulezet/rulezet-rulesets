rule Trojan_Win64_Vidar_ABV_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 47 01 0f b6 f8 48 8d 52 01 0f b6 4c 3c 50 42 8d 04 01 44 0f b6 c0 42 0f b6 44 04 50 88 44 3c 50 42 88 4c 04 50 0f b6 44 3c 50 03 c1 0f b6 c0 0f b6 4c 04 50 30 4a ff 49 83 e9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}