rule Trojan_Win32_Qakbot_PI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 31 31 38 64 65 38 31 62 33 30 31 33 31 64 36 63 63 33 33 61 31 35 34 30 32 37 33 31 30 33 37 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}