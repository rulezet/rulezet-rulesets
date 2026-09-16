rule Trojan_Win64_Amadey_AMD_MTB_3{
	meta:
		description = "Trojan:Win64/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 15 c1 7d 07 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8d 15 c1 7d 07 00 48 8b cf 48 89 05 67 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 c2 7d 07 00 48 8b cf 48 89 05 58 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 c3 7d 07 00 48 8b cf 48 89 05 49 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 bc 7d 07 00 48 8b cf 48 89 05 3a 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 bd 7d 07 00 48 8b cf } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}