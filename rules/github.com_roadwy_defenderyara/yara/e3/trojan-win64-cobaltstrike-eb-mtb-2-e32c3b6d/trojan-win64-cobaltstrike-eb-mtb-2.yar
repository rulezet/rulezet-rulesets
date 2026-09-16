rule Trojan_Win64_Cobaltstrike_EB_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 44 8b c0 48 8b 93 f8 00 00 00 48 8b 8b a8 00 00 00 48 2b cf 48 8b 42 50 48 0f af c1 48 89 42 50 49 83 e8 01 75 dd 48 8b 83 d8 00 00 00 8b 88 38 01 } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}