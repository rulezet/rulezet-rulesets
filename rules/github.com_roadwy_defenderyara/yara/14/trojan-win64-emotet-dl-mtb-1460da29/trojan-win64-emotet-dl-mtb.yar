rule Trojan_Win64_Emotet_DL_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 99 41 f7 fa 48 8b 05 [0-04] 48 63 d2 44 8a 04 10 45 32 04 0b 45 88 04 09 48 ff c1 48 81 f9 9d 0b 00 00 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}