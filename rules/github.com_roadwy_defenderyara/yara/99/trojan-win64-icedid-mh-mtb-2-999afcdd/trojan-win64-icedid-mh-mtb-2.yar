rule Trojan_Win64_IcedID_MH_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 08 48 8b 04 24 66 3b ed 74 ?? 48 8b 44 24 08 48 ff c0 3a d2 74 ?? 48 ff c8 48 89 44 24 30 eb } 		$a_01_1 = {75 69 73 62 61 64 79 75 67 61 75 73 62 64 6a 61 73 79 75 64 6a 61 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}