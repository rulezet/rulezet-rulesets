rule Trojan_Win64_Emotet_PAO_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ed 2b d5 83 c5 ?? c1 fa ?? 8b c2 c1 e8 ?? 03 c2 48 98 48 6b c0 ?? 49 03 c1 0f b6 04 08 41 8d 48 ff 41 32 44 32 fd 88 46 fd b8 ?? ?? ?? ?? f7 e9 2b d1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}