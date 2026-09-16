rule Trojan_Win64_Tedy_RR_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 03 ce 48 89 8c 24 e0 00 00 00 48 33 94 24 08 01 00 00 48 89 94 24 d8 00 00 00 4c 8b ac 24 00 01 00 00 4d 03 dd 4c 89 9c 24 d0 00 00 00 48 8b bc 24 f8 00 00 00 48 33 f7 44 89 84 24 f4 00 00 00 45 8b f9 45 2b f8 41 83 ff 20 7e 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}