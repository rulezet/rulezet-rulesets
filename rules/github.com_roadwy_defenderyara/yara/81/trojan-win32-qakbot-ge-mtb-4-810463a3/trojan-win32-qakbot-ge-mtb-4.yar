rule Trojan_Win32_Qakbot_GE_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2a de 0f b6 c6 80 eb [0-01] 2b 44 24 [0-01] 2d 4b c9 00 00 a3 [0-04] 8b 84 31 [0-04] 05 ?? ?? 06 01 88 1d [0-04] a3 [0-04] 89 84 31 [0-04] 83 c6 04 81 fe 7a 22 00 00 73 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}