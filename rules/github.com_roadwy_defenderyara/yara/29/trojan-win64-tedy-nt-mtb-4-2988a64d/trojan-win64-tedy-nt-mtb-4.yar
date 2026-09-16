rule Trojan_Win64_Tedy_NT_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 75 73 43 6c 61 73 73 } 		$a_01_1 = {4b 65 79 20 64 6f 65 73 6e 74 20 65 78 69 73 74 20 21 } 		$a_01_2 = {54 54 52 73 20 49 6e 74 65 72 6e 61 6c 20 53 6c 6f 74 74 65 64 } 		$a_01_3 = {57 4f 52 4b 20 4f 4e 4c 59 20 4f 4e 20 45 41 43 } 		$a_01_4 = {76 76 73 6b 32 6e 4a 57 50 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}