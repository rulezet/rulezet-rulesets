rule Trojan_Win32_Qakbot_RT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1d 45 12 eb 06 1a 41 ?? 33 04 5f 03 db 4b 03 d2 81 e8 e8 ef 00 00 33 c7 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}