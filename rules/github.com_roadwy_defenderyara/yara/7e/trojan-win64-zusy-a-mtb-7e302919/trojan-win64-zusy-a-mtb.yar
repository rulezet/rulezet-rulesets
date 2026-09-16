rule Trojan_Win64_Zusy_A_MTB{
	meta:
		description = "Trojan:Win64/Zusy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 85 c0 79 1d 49 8b 4c 24 08 49 2b 0c 24 48 c1 f9 05 48 ff c9 49 63 c7 48 3b c1 73 05 41 ff c7 eb 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}