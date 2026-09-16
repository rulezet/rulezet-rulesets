rule Trojan_Win64_IcedID_EG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 2b 00 00 00 83 c0 3d 66 3b e4 74 0e 48 83 ec 58 b8 16 00 00 00 66 3b c9 74 0f 66 89 44 24 2a b8 3f 00 00 00 66 3b c9 74 49 83 c0 3d 66 89 44 24 28 66 3b c9 74 c9 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}