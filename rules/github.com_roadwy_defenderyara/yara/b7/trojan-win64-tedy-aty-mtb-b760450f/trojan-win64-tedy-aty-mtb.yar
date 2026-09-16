rule Trojan_Win64_Tedy_ATY_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 89 ca 41 8d 0c 18 42 32 4c 00 10 48 c1 fa 08 31 d1 4c 89 ca 49 c1 f9 18 48 c1 fa 10 31 d1 44 31 c9 42 88 4c 00 10 49 ff c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}