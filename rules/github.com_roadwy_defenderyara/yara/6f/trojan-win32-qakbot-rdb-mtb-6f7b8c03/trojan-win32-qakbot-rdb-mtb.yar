rule Trojan_Win32_Qakbot_RDB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d1 8b 4d fc 2b d7 8b c7 83 e0 7f 8a 04 18 32 04 0f 88 04 3a 47 83 ee 01 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}