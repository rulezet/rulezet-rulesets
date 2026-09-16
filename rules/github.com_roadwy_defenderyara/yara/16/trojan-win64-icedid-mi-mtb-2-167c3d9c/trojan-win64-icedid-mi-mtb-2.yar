rule Trojan_Win64_IcedID_MI_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 20 48 89 04 24 66 3b ed 74 ?? 88 08 48 8b 04 24 3a db 74 ?? 48 ff c0 48 89 04 24 66 3b d2 74 } 		$a_01_1 = {79 75 67 68 6f 69 61 73 64 6d 69 61 6f 73 64 6e 75 61 73 64 6a 6b 61 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}