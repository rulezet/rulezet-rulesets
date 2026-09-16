rule Trojan_Win32_Qakbot_RQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 8b 54 24 0c 8a c1 66 2b 17 f6 ea 66 89 54 24 0c 8a c8 0f b7 c2 99 80 c1 48 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}