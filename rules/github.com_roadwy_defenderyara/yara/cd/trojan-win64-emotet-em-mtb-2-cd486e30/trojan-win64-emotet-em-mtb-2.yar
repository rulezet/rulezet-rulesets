rule Trojan_Win64_Emotet_EM_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 29 d1 4d 63 c9 42 0f b6 04 08 32 04 0b 41 88 04 08 48 83 c1 01 4c 39 d9 75 c2 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}