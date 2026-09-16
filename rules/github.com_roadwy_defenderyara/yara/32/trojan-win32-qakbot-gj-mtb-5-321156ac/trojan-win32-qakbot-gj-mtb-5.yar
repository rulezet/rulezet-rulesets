rule Trojan_Win32_Qakbot_GJ_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 3b 05 [0-04] 90 18 a1 [0-04] 80 c3 ?? 02 db 81 c6 [0-04] 2a da 89 35 [0-04] 02 1d [0-04] 89 b4 28 [0-04] 83 c5 04 81 fd 4e 07 00 00 73 1d 8b 35 [0-04] 8b 0d [0-04] 8b 3d [0-04] 8b 15 [0-04] e9 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}