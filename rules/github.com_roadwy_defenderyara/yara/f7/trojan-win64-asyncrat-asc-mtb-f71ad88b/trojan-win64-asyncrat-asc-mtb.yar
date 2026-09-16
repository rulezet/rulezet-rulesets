rule Trojan_Win64_AsyncRat_ASC_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 98 48 8b 95 a8 04 00 00 48 01 d0 0f b6 00 32 85 a7 04 00 00 48 8b 8d 90 04 00 00 8b 95 bc 04 00 00 48 63 d2 88 04 11 83 85 bc 04 00 00 01 8b 95 bc 04 00 00 8b 85 5c 04 00 00 39 c2 } 		$a_01_1 = {4d 89 c1 49 89 c8 48 89 c1 48 8b 05 5a 6b 00 00 ff d0 48 8b 85 78 04 00 00 48 8d 50 30 48 8b 85 70 04 00 00 48 8b 80 88 00 00 00 48 83 c0 10 48 89 c1 48 8b 85 40 04 00 00 48 c7 44 24 20 00 00 00 00 41 b9 08 00 00 00 49 89 d0 48 89 ca 48 89 c1 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}