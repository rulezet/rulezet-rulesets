rule Trojan_Win64_Emotet_DK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 89 c8 41 29 d0 4d 63 c0 4c 8b 0d [0-04] 47 0f b6 04 01 44 32 44 0c 20 45 88 04 0a 48 83 c1 01 48 81 f9 9d 0b 00 00 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}