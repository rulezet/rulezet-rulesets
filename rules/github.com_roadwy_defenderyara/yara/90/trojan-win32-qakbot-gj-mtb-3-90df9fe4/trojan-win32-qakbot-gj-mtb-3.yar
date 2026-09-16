rule Trojan_Win32_Qakbot_GJ_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e6 00 31 fe 8b 7d fc 55 33 2c e4 0b ab [0-04] 83 e1 00 31 e9 5d fc f3 a4 56 c7 04 e4 ff ff 0f 00 59 ff b3 [0-04] 8f 45 fc ff 75 fc 58 53 81 04 e4 [0-04] 29 1c e4 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}