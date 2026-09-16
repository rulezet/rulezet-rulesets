rule Trojan_Win32_Qakbot_BS_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.BS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b f2 71 89 cf 01 f7 6b f2 71 89 cb 01 f3 83 c3 6d 6b f2 71 89 44 24 30 89 c8 01 f0 83 c0 0d 8b 00 6b f2 71 01 f1 83 c1 11 8b 09 33 0b 8b 74 24 78 89 f3 03 5c 24 7c 89 44 24 2c 8b 44 24 30 2b 07 8b 7c 24 2c 01 c7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}