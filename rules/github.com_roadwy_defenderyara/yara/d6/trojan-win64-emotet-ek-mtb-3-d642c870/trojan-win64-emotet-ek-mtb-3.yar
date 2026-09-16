rule Trojan_Win64_Emotet_EK_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 04 40 49 0f af c3 48 03 d0 49 8d 46 02 48 03 c7 48 0f af c6 48 8d 04 40 48 2b d0 48 8b 44 24 28 49 03 d5 49 ff c5 44 88 0c 02 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}