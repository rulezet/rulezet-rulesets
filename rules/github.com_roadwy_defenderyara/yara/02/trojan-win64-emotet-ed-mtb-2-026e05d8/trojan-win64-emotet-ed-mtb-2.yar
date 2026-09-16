rule Trojan_Win64_Emotet_ED_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b ca d1 e9 03 ca c1 e9 04 89 4c 24 68 8b 4c 24 68 f7 e1 c1 ea 06 89 54 24 68 49 8b d2 81 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}