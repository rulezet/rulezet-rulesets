rule Trojan_Win64_Tedy_NT_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {84 c0 0f 84 36 01 00 00 40 32 f6 40 88 74 24 ?? e8 d6 f9 ff ff 8a d8 8b 0d 8a dd 05 00 83 f9 01 0f 84 23 01 00 00 85 c9 75 4a c7 05 73 dd 05 00 01 00 00 00 48 8d 15 6c 75 03 00 48 8d 0d 15 75 03 00 } 		$a_01_1 = {52 4f 53 48 61 6e 64 6c 65 72 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}