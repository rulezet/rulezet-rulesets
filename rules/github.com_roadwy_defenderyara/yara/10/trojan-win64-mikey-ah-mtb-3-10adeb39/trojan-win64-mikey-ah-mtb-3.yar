rule Trojan_Win64_Mikey_AH_MTB_3{
	meta:
		description = "Trojan:Win64/Mikey.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 0f be 00 83 f0 ?? 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 88 01 eb } 		$a_03_1 = {48 8d 84 04 48 1f 00 00 b9 ?? 00 00 00 48 6b c9 ?? c6 04 08 ?? b8 ?? 00 00 00 48 6b c0 ?? 48 8d 84 04 48 1f 00 00 } 	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}