rule Trojan_Win64_IcedID_MX_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ec c1 fa ?? 8b c2 c1 e8 ?? 03 c2 48 98 48 8d 0c 40 49 63 c4 41 83 c4 01 48 8d 14 c8 48 8b 44 24 28 42 0f b6 8c 32 f0 a1 06 00 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}