rule Trojan_Win64_IcedID_BB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 30 48 8d 44 01 18 eb dd 48 8b 54 24 28 4c 8b 84 24 c0 01 00 00 66 3b f6 74 0d 48 8b c1 48 89 44 24 30 66 3b ed 74 1f 41 8a 04 00 88 04 0a e9 } 		$a_01_1 = {79 68 61 75 64 69 6a 6d 64 73 69 66 75 68 79 61 73 64 69 6a 61 6b 64 73 6d 6a 64 73 75 68 66 79 61 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}