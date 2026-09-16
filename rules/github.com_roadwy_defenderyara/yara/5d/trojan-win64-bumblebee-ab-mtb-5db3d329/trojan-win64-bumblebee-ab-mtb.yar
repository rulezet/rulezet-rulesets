rule Trojan_Win64_Bumblebee_AB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b 80 88 00 00 00 49 8b f8 49 8b 88 18 02 00 00 48 0f af c0 48 69 c0 ?? ?? 00 00 49 89 80 88 00 00 00 49 8b 80 b0 01 00 00 48 05 ?? ?? 00 00 48 09 81 98 01 00 00 49 8b c8 49 8b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}