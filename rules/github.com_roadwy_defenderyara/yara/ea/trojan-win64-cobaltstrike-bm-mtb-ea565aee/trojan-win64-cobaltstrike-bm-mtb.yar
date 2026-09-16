rule Trojan_Win64_CobaltStrike_BM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 ff c0 49 63 c8 48 8d 54 24 30 48 03 d1 0f b6 0a 41 88 09 44 88 12 41 0f b6 09 41 03 ca 0f b6 d1 0f b6 4c 14 30 32 0c 1e 88 0b 48 ff c3 48 83 ed 01 75 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}