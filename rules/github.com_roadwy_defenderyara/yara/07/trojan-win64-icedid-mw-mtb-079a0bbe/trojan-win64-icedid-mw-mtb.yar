rule Trojan_Win64_IcedID_MW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ec 41 03 d4 c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c4 41 ff c4 6b d2 1d 2b c2 48 63 c8 48 8b 44 24 28 42 8a 8c 31 ?? ?? ?? ?? 41 32 0c 00 43 88 0c 18 49 ff c0 44 3b 64 24 20 72 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}