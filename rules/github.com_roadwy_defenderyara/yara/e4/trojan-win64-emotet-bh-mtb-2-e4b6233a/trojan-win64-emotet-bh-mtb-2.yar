rule Trojan_Win64_Emotet_BH_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 63 ca 4c 8b 55 ?? 43 0f b6 14 0a 31 d1 41 88 cb 4c 8b 8d ?? ?? ?? ?? 48 63 75 ?? 45 88 1c 31 8b 45 ?? 83 c0 ?? 89 45 ?? e9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}