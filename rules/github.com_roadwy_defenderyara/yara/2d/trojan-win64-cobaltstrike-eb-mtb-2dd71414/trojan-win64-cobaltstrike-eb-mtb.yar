rule Trojan_Win64_Cobaltstrike_EB_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c3 31 c0 39 c6 7e 15 48 89 c2 83 e2 07 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb e7 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}