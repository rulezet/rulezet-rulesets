rule Trojan_Win64_Amadey_AMD_MTB{
	meta:
		description = "Trojan:Win64/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 f7 e9 48 01 ca 48 d1 fa 48 89 cb 48 c1 f9 3f 48 29 ca 48 85 d2 0f 8e a4 00 00 00 48 8b 44 24 68 48 89 d1 48 89 c6 48 } 		$a_01_1 = {48 89 44 24 18 48 8b 10 48 8d 59 ff 48 89 1c 24 48 8b 1a ff d3 48 8b 44 24 08 48 89 44 24 10 48 8b 4c 24 18 48 8b 11 48 8b 4c 24 30 48 83 c1 fe } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}