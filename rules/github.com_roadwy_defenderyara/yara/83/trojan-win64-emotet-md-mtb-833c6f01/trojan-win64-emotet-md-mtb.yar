rule Trojan_Win64_Emotet_MD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 49 8b c9 32 14 18 4b 8d 04 1b 49 0f af c9 49 0f af c8 49 2b cb 49 0f af c9 49 03 ca 48 2b c8 48 8d 04 4e 48 ff c6 48 03 c8 88 14 39 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}