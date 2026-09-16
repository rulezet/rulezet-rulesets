rule Trojan_Win32_Qakbot_GP_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 e4 ff ff 0f 00 59 51 33 0c [0-01] 33 8b [0-04] 83 e0 00 31 c8 59 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 89 4d [0-01] 8b 8b [0-04] 01 c1 51 8b 4d [0-01] 58 ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}