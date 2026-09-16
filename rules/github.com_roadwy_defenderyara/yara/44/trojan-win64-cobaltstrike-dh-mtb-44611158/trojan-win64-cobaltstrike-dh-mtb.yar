rule Trojan_Win64_Cobaltstrike_DH_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 c1 41 83 e1 ?? 47 8a 0c 08 44 32 0c 01 48 ff c0 44 88 48 ?? eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}