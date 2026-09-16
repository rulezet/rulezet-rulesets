rule Trojan_Win64_Emotet_EH_MTB_5{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 48 c7 44 24 58 fe 60 00 00 83 fa 64 0f 85 a4 00 00 00 c7 44 24 34 64 d5 00 00 4c 89 44 24 20 c1 6c 24 34 06 81 74 24 34 75 f9 0f 00 c7 44 24 30 1e ae 00 00 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}