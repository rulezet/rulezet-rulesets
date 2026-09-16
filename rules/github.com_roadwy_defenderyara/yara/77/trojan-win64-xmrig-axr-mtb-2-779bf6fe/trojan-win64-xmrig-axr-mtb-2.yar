rule Trojan_Win64_Xmrig_AXR_MTB_2{
	meta:
		description = "Trojan:Win64/Xmrig.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 48 89 5c 24 40 48 89 5c 24 48 41 b8 15 00 00 00 48 8d 15 5d 6c 04 00 48 8d 4c 24 30 e8 ?? ?? ?? ?? ?? 0f 57 c0 0f 11 44 24 50 48 89 5c 24 60 48 89 5c 24 68 41 b8 16 00 00 00 48 8d 15 4b 6c 04 00 48 8d 4c 24 50 } 		$a_03_1 = {0f 57 c0 0f 11 45 d0 48 89 5d e0 48 89 5d e8 41 b8 15 00 00 00 48 8d 15 f8 6b 04 00 48 8d 4d d0 e8 ?? ?? ?? ?? ?? 0f 57 c0 0f 11 45 f0 48 89 5d 00 48 89 5d 08 41 b8 17 00 00 00 48 8d 15 ea 6b 04 00 48 8d 4d f0 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}