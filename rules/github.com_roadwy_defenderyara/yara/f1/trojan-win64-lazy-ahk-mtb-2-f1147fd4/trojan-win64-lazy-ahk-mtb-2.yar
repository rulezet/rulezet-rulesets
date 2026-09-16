rule Trojan_Win64_Lazy_AHK_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 0f b7 fb 66 44 0f a3 ff 66 0f ab d7 42 8b bc 19 ?? ?? ?? ?? 66 45 3b e8 41 80 f8 ?? 4a 8d 3c 1f 49 3b fb 0f } 		$a_03_1 = {0f be ca 48 1b d0 66 41 23 d7 f9 41 33 c9 e9 00 00 00 00 44 69 c9 ?? ?? ?? ?? 66 0f a4 d2 ?? 0f 94 c6 41 0f b6 10 4d 8d 40 ?? 41 f6 c6 ?? 84 d2 0f } 	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}