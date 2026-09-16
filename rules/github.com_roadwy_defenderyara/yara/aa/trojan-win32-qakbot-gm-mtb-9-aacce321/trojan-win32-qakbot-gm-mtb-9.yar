rule Trojan_Win32_Qakbot_GM_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 04 e4 31 0c e4 ff 93 [0-04] 51 83 e1 00 31 c1 83 a3 [0-04] 00 09 8b [0-04] 59 29 c9 8f 45 [0-01] 0b 4d [0-01] 8f 45 [0-01] 8b 45 [0-01] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 51 8b 8b [0-04] 50 8f 45 [0-01] 01 4d [0-01] ff 75 [0-01] 58 59 ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}