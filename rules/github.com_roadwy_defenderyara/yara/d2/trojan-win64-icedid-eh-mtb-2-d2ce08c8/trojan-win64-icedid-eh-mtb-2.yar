rule Trojan_Win64_IcedID_EH_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 3a ff 74 00 48 89 54 24 10 48 89 4c 24 08 66 3b db 74 86 83 c0 24 66 89 44 24 54 3a f6 74 8b 33 c0 66 89 44 24 76 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}