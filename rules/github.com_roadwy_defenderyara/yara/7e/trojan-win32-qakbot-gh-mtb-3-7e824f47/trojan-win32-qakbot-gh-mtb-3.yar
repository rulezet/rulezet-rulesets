rule Trojan_Win32_Qakbot_GH_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c1 3c 73 0d 01 89 0d [0-04] 89 54 24 [0-01] 89 15 [0-04] 89 0b 83 c3 04 0f b6 c8 66 83 c1 [0-01] 89 5c 24 [0-01] 66 03 4c 24 [0-01] 83 6c 24 [0-01] 01 66 8b f9 89 7c 24 [0-01] 66 89 3d [0-04] 0f b7 d9 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}