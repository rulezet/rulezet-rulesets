rule Trojan_Win64_Cobaltstrike_EN_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 63 c8 41 8d 40 82 41 ff c0 30 44 0c 28 41 83 f8 0c 72 ec } 		$a_01_1 = {57 69 6e 64 6f 77 73 50 72 6f 6a 65 63 74 5f 62 69 6e 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}