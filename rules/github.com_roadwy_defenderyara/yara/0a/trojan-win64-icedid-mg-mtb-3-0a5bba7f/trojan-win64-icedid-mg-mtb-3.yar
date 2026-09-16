rule Trojan_Win64_IcedId_MG_MTB_3{
	meta:
		description = "Trojan:Win64/IcedId.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 08 8a 09 66 3b c0 74 00 88 08 48 8b 04 24 3a db 74 1a 4c 89 44 24 18 48 89 54 24 10 3a f6 74 17 48 8b 44 24 08 48 ff c0 3a c9 74 25 48 ff c0 48 89 04 24 3a e4 74 e9 } 		$a_01_1 = {62 69 61 79 75 73 64 6a 61 73 64 75 67 61 79 73 68 67 64 6a 61 6b 73 61 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}