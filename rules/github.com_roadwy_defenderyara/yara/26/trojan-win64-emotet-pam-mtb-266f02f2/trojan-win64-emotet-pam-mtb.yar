rule Trojan_Win64_Emotet_PAM_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 c1 fa ?? c1 ea ?? 01 d0 83 e0 ?? 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}