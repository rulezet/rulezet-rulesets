rule Trojan_Win64_Cobaltstrike_EM_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 1e ff 41 03 d0 c1 fa 09 8b ca c1 e9 1f 03 d1 69 ca 7b 03 00 00 44 2b c1 41 fe c0 41 32 c0 40 32 c5 88 43 ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}