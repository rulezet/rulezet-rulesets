rule Trojan_Win32_Qakbot_AR_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 f0 8b 45 08 8b 08 2b ce 8b 55 08 89 0a 5e 8b e5 5d } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}