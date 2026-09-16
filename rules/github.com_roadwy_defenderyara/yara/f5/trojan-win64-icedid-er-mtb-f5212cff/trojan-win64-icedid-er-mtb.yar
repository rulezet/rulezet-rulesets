rule Trojan_Win64_Icedid_ER_MTB{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 43 38 48 63 93 c0 02 00 00 48 8b 4b 10 0f b6 14 0a 42 32 14 18 48 8b 43 60 41 88 14 03 48 81 7b 20 45 3b 00 00 73 12 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}