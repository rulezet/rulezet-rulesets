rule Trojan_Win64_Emotet_EK_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 f8 4c 63 ca 4c 8b 55 b0 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d e8 0b 00 00 8b 4d 24 03 4d 28 2b 4d 28 48 63 f1 45 88 1c 31 8b 45 24 83 c0 01 89 45 24 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}