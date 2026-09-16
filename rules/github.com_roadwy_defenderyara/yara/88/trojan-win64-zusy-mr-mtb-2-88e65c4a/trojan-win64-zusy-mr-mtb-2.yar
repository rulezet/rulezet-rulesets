rule Trojan_Win64_Zusy_MR_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 84 24 ad 01 00 00 d3 c6 84 24 ae 01 00 00 67 c6 84 24 af 01 00 00 5b c7 84 24 b0 01 00 00 cf be 3a 46 } 		$a_03_1 = {41 8b cb 41 8b c3 48 c1 e9 10 25 ff 00 04 00 83 e1 06 89 ?? ?? 72 05 00 48 81 c9 29 00 00 01 48 f7 d1 ?? ?? 0d 80 4f 05 00 48 ?? ?? 79 4f 05 00 3c 01 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}