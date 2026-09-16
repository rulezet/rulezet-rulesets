rule Trojan_Win64_Cobaltstrike_EM_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 53 5f b0 c6 fc ae 75 fd 57 59 53 5e 8a 06 30 07 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}