rule Trojan_Win32_Qakbot_PT_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.PT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 89 45 08 8b 45 08 80 78 02 00 74 21 33 c0 ba 80 00 00 00 8b c8 80 b1 20 f8 09 00 09 41 3b ca 72 f4 80 b0 50 f0 09 00 aa 40 3b c2 72 f4 8b 4d 0c e8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}