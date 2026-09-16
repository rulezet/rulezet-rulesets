rule Trojan_Win64_Emotet_ED_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b 4c 24 08 41 d3 e1 44 89 4c 24 3c 41 89 c1 44 89 ca 4c 8b 44 24 28 41 8a 0c 10 44 28 d9 4c 8b 54 24 18 41 88 0c 12 83 c0 20 44 8b 4c 24 24 44 39 c8 89 44 24 0c } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}