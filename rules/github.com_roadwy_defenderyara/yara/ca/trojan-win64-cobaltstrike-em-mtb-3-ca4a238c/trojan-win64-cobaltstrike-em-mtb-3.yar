rule Trojan_Win64_Cobaltstrike_EM_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 63 cb 31 d2 4c 89 e1 ff 15 ?? ?? ?? ?? 49 89 c0 31 c0 48 89 c2 83 e2 07 8a 14 17 32 14 06 41 88 14 00 48 ff c0 39 c3 7f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}