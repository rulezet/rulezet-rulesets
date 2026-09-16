rule Trojan_Win64_Emotet_EH_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 8d 04 0a 48 03 c8 48 8d 04 49 49 8b cb 49 ff c3 48 2b c8 44 88 04 39 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}