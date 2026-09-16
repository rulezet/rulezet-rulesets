rule Trojan_Win64_IcedID_SMG_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.SMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 01 eb 4d 63 db 44 01 c2 c1 fa 05 29 c2 0f af d7 29 d1 48 63 c9 41 0f b6 04 0a 42 32 04 06 49 83 c0 01 44 39 c3 43 88 04 19 0f 87 57 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}