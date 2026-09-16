rule Trojan_Win64_Mikey_AH_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 c7 32 04 29 88 01 48 8d 49 ?? 48 83 ea ?? 75 } 		$a_01_1 = {f3 0f 6f 4c 01 e0 f3 0f 7f 40 d0 0f 57 ce f3 0f 7f 48 e0 48 3b f2 72 } 	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}