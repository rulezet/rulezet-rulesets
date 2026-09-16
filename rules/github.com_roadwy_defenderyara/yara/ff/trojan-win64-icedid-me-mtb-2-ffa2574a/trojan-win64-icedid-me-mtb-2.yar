rule Trojan_Win64_IcedID_ME_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 ff c0 41 f7 ec c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c4 41 ff c4 6b d2 ?? 2b c2 48 63 c8 48 8b 44 24 ?? 42 0f b6 8c 31 ?? ?? ?? ?? 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}