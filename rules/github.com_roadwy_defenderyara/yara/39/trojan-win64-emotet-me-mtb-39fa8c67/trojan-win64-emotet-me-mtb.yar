rule Trojan_Win64_Emotet_ME_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c8 48 2b f0 b8 ?? ?? ?? ?? 41 f7 e8 c1 fa 03 8b c2 c1 e8 1f 03 d0 49 63 c0 41 83 c0 01 48 63 ca 48 6b c9 19 48 03 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0e 41 88 01 49 83 c1 01 44 3b c5 72 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}