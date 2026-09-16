rule Trojan_Win64_Mikey_AH_MTB_2{
	meta:
		description = "Trojan:Win64/Mikey.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 c6 32 04 0b 88 04 0e 45 02 f7 48 ff c1 48 3b cf 72 } 		$a_03_1 = {0f b6 02 8b c8 c1 e9 ?? c0 e0 ?? 0a c8 88 0a 48 8d 52 ?? 48 83 ef ?? 75 } 	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}