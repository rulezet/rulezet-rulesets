rule Trojan_Win64_Convagent_ARR_MTB{
	meta:
		description = "Trojan:Win64/Convagent.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e7 c1 ea ?? 0f b7 c2 6b c8 ?? 0f b7 c7 41 03 fc 66 2b c1 66 83 c0 ?? 66 31 06 48 8d 76 02 } 		$a_03_1 = {44 33 c1 41 69 c8 ?? ?? ?? ?? 44 0f b7 00 48 8d 40 ?? 45 85 c0 75 } 	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*5) >=20
 
}