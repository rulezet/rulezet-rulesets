rule Trojan_Win64_Fabookie_RPY_MTB_2{
	meta:
		description = "Trojan:Win64/Fabookie.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 9d 60 01 00 00 43 0f b6 3c 13 49 8b c4 49 f7 e1 48 c1 ea 03 48 8d 04 52 48 c1 e0 02 49 8b c9 48 2b c8 42 0f be 04 29 44 03 c0 44 03 c7 41 81 e0 ff 00 00 80 7d 0d 41 ff c8 41 81 c8 00 ff ff ff 41 ff c0 49 63 c8 42 0f b6 04 19 43 88 04 13 42 88 3c 19 49 ff c1 49 ff c2 48 83 ee 01 75 9f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}