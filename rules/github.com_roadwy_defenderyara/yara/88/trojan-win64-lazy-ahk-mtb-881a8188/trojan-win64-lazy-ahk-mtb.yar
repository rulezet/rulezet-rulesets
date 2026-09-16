rule Trojan_Win64_Lazy_AHK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6f 4d 00 f3 0f 6f 05 ?? ?? ?? ?? 0f 57 c8 66 0f 7f 4d 00 48 8d 45 00 49 8b cd } 		$a_03_1 = {48 8b 45 00 48 89 85 f0 00 00 00 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 45 00 48 8b 45 00 48 89 85 ?? 00 00 00 49 8b c7 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}