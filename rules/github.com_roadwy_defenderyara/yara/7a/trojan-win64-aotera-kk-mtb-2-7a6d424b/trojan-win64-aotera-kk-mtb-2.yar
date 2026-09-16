rule Trojan_Win64_Aotera_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Aotera.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8b c9 46 0f b6 4c 0e ?? 49 03 d1 49 b9 ?? ?? ?? ?? ?? ?? ?? ?? 49 0f af d1 4c 8b ca 49 c1 e9 1c 49 33 d1 ff c1 44 3b c1 } 		$a_03_1 = {49 03 d0 4c 8b c2 49 c1 e8 ?? 4c 33 c2 49 b9 ?? ?? ?? ?? ?? ?? ?? ?? 4d 0f af c1 4d 8b c8 49 c1 e9 ?? 4d 33 c1 49 b9 ?? ?? ?? ?? ?? ?? ?? ?? 4d 0f af c1 4d 8b c8 49 c1 e9 ?? 4d 33 c1 44 8b c9 4e 89 44 c8 ?? ff c1 83 f9 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}