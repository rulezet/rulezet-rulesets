rule Trojan_Win32_Qakbot_GP_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 e4 ff ff 0f 00 59 89 4d [0-01] 33 4d [0-01] 0b 8b [0-04] 83 e0 00 09 c8 8b 4d [0-01] 54 c7 04 e4 [0-04] 8f 83 [0-04] 21 8b [0-04] 6a 00 89 3c [0-01] 50 5f 03 bb [0-04] 89 f8 5f ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}