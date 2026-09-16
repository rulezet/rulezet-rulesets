rule Trojan_Win32_Qakbot_GH_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 57 a1 [0-04] a3 [0-04] 8b 0d [0-04] 8b 11 89 15 [0-04] 8b 15 [0-04] a1 [0-04] 50 8f 05 [0-04] 8b 3d [0-04] 89 15 [0-04] 8b c7 eb 00 eb 00 eb 00 eb 00 eb 00 eb 00 bb } 		$a_02_1 = {8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b db 8b c8 8b d1 89 15 [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5f 5b 5d c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}