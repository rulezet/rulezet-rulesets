rule Trojan_Win64_Lazy_EM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 1d c1 01 48 83 ec 10 48 31 14 24 48 31 d0 83 44 24 08 28 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}