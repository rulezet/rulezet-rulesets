rule Trojan_Win64_CobaltStrike_AI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 44 02 d9 44 02 df 41 0f b6 cb 8a 44 8d 08 41 30 06 8b 44 8d 08 49 ff c6 31 44 95 08 42 8b 44 a5 08 41 8d 0c 00 42 31 4c 95 08 49 ff cf 0f } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}