rule Trojan_Win64_CobaltStrike_CMP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 44 24 24 83 f8 41 7c 17 0f b7 44 24 24 83 f8 5a 7f 0d 0f b7 44 24 24 83 c0 20 66 89 44 24 24 0f b7 44 24 28 83 f8 41 7c 17 0f b7 44 24 28 83 f8 5a 7f 0d 0f b7 44 24 28 83 c0 20 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}