rule Trojan_Win64_Emotet_EN_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 01 32 0c 2b 88 0b 48 ff c3 48 83 ee 01 75 be } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}