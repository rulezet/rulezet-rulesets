rule Trojan_Win64_IcedID_EM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 3b d1 72 0e 8b c6 25 43 4a 00 00 48 31 83 28 01 00 00 83 c1 03 48 63 c1 48 3b c2 75 e2 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}