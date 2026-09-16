rule Trojan_Win64_Amadey_AMD_MTB_2{
	meta:
		description = "Trojan:Win64/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 38 41 b8 50 00 00 00 89 5c 24 30 45 33 c9 c7 44 24 28 03 00 00 00 49 8b ce 48 89 5c 24 20 ff 15 ?? ?? ?? ?? 48 8b f0 48 8b 44 24 48 4c 8b c0 48 83 78 18 10 72 03 4c 8b 00 48 89 5c 24 38 48 8d 15 76 c0 08 00 89 5c 24 30 45 33 c9 48 89 5c 24 28 48 8b ce 48 89 5c 24 20 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}