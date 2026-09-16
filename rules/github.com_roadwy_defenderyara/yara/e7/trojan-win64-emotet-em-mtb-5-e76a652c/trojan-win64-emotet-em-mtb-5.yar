rule Trojan_Win64_Emotet_EM_MTB_5{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 32 44 0c 20 49 2b d2 4a 8d 0c 5d fe ff ff ff 49 0f af d1 49 2b d2 49 03 d3 48 0f af c1 48 03 c7 48 ff c7 48 8d 0c 50 46 88 04 31 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}