rule Trojan_Win64_SamScissors_EM_MTB{
	meta:
		description = "Trojan:Win64/SamScissors.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 03 d6 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 0f 44 2b f1 41 ff c6 44 89 6c 24 30 4c 89 6c 24 38 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}