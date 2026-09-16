rule Trojan_Win64_Emotet_EM_MTB_6{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 b4 44 89 c0 89 55 b0 99 44 8b 45 b4 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 b0 41 31 d2 45 88 d3 48 8b 8d d0 0b 00 00 8b 55 18 2b 55 1c 03 55 1c 4c 63 ca 46 88 1c 09 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}