rule Trojan_Win64_Emotet_BR_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff c2 41 ff c0 0f b6 0c 08 41 32 4c 11 ff 88 4a ff 48 ff cb } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}