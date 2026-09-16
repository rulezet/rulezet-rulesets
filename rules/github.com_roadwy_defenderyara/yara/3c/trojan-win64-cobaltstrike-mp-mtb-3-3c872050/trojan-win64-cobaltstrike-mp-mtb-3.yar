rule Trojan_Win64_CobaltStrike_MP_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 63 c3 49 8b c7 ff c3 49 f7 e0 48 c1 ea 04 48 8d 04 d2 48 03 c0 4c 2b c0 4d 0f af c3 42 8a 44 05 87 42 32 04 0e 41 88 01 49 ff c1 81 fb 00 ba 01 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}