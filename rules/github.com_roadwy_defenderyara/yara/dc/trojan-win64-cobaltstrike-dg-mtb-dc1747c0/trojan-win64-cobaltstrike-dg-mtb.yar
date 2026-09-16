rule Trojan_Win64_Cobaltstrike_DG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b fb 48 c1 f9 ?? 0f b6 c9 0f bf 14 48 c1 ea ?? 83 e2 ?? c1 ff ?? 85 d2 74 } 		$a_03_1 = {80 30 ee ff c1 48 8d 40 ?? 81 f9 ?? ?? ?? ?? 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}