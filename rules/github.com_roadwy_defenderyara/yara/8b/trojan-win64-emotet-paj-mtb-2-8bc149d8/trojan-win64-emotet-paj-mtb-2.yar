rule Trojan_Win64_Emotet_PAJ_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 36 00 00 00 f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 fc 00 00 00 33 c8 8b c1 8b 4c 24 34 8b 54 24 30 2b d1 8b ca 03 4c 24 34 48 63 c9 48 8b 94 24 f0 00 00 00 88 04 0a e9 60 ff ff ff 48 8d 0d a4 e6 02 00 ff 94 24 f0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}