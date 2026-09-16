rule Trojan_Win64_IcedID_EB_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc ba 4f ec c4 4e 89 c8 f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 34 29 c1 89 c8 } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}