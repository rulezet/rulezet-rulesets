rule Trojan_Win64_Rozena_RD_MTB{
	meta:
		description = "Trojan:Win64/Rozena.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 4a 40 8b 48 48 89 4a 48 0f b7 48 4c 66 89 4a 4c 33 c9 ba ce 01 00 00 44 8d 49 40 ff 15 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}