rule Trojan_Win64_Tedy_NT_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 8b c0 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 2b c8 0f b6 44 0d ?? 4b 8d 0c 39 41 00 41 ?? 49 8b c0 48 f7 e1 48 c1 ea } 		$a_01_1 = {72 75 6e 61 73 } 		$a_01_2 = {42 61 63 6b 44 6f 6f 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}