rule Trojan_Win64_Cobaltstrike_EB_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 83 c0 01 f7 ed c1 fa 03 8b c2 c1 e8 1f 03 d0 48 63 c5 83 c5 01 48 63 ca 48 6b c9 21 48 03 c8 48 8b 44 24 38 42 0f b6 8c 31 b0 98 04 00 41 32 4c 00 ff 41 88 4c 18 ff } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}