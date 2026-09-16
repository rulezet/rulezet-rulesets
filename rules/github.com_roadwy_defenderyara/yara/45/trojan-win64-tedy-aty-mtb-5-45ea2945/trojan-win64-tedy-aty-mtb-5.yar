rule Trojan_Win64_Tedy_ATY_MTB_5{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 c0 10 ff d0 ff 15 ?? ?? ?? ?? 33 d2 b9 c8 00 00 00 f7 f1 8b c2 83 c0 64 4c 8d 0d 3c ff ff ff 44 8b c0 ba ea 03 00 00 48 8b 4c 24 60 } 		$a_03_1 = {48 83 c0 10 ff d0 ff 15 ?? ?? ?? ?? 33 d2 b9 96 00 00 00 f7 f1 8b c2 83 c0 32 4c 8d 0d be fe ff ff 44 8b c0 ba eb 03 00 00 48 8b 4c 24 60 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}