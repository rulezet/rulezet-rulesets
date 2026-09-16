rule Trojan_Win64_IcedID_AW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 08 48 8b 04 24 3a ff 74 00 48 ff c0 48 89 04 24 66 3b e4 74 00 48 8b 44 24 08 48 ff c0 66 3b ff 74 9c 48 ff c8 48 89 44 24 30 e9 } 		$a_01_1 = {48 8b 4c 24 08 8a 09 66 3b db 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}