rule Trojan_Win64_Zusy_EM_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b 40 04 41 03 c2 48 98 48 8d 0c 40 41 8b 00 41 03 c3 49 83 c0 08 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}