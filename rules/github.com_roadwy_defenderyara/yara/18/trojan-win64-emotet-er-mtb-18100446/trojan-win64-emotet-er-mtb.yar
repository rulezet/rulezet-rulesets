rule Trojan_Win64_Emotet_ER_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c8 48 63 c1 42 0f b6 0c 00 43 32 4c 0b ff 41 88 49 ff } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}