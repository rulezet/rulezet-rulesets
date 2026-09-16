rule Trojan_Win32_Qakbot_BH_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 08 88 14 01 ff 47 50 8b 87 b8 00 00 00 8b 4f 50 35 83 00 75 06 09 47 28 29 47 20 8b 47 78 88 1c 01 ff 47 50 8b 47 68 2d [0-04] 01 87 b8 00 00 00 8b 87 ac 00 00 00 35 [0-04] 29 47 14 8b 87 94 00 00 00 8b 4f 68 03 c8 81 f1 [0-04] 03 c8 8b 47 44 33 47 08 2d [0-04] 89 8f 94 00 00 00 09 47 14 81 fe [0-04] 0f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}