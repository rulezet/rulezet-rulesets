rule Trojan_Win64_Tedy_AH_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 48 0f 7e f7 66 0f 73 de ?? 66 49 0f 7e f7 4c 8d 74 24 78 66 48 0f 7e fe 49 83 ff ?? 4c 0f 47 f6 } 		$a_03_1 = {44 8b c0 41 81 f0 ?? ?? ?? ?? 41 c1 c8 ?? 8b d0 81 f2 ?? ?? ?? ?? c1 ca ?? 8b c8 81 f1 ?? ?? ?? ?? c1 c9 ?? 35 ?? ?? ?? ?? c1 c8 ?? 44 89 44 24 30 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}