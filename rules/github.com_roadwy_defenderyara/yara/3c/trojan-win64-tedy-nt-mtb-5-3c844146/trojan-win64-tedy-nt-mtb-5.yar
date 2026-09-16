rule Trojan_Win64_Tedy_NT_MTB_5{
	meta:
		description = "Trojan:Win64/Tedy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d 8f 88 02 00 48 89 44 24 ?? 48 89 0b 48 8d 53 ?? 0f 57 c0 c6 44 24 ?? 01 48 8d 4c 24 ?? 0f 11 02 e8 } 		$a_03_1 = {45 33 c9 4c 8d 44 24 ?? ba f4 01 00 00 48 8d 4c 24 ?? e8 f4 5b ff ff 48 8d 15 ed 6b 03 00 48 8d 4c 24 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}