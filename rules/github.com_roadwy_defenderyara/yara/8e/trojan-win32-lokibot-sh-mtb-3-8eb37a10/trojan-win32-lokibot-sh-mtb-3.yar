rule Trojan_Win32_Lokibot_SH_MTB_3{
	meta:
		description = "Trojan:Win32/Lokibot.SH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 13 b0 86 02 cb c0 c9 03 f6 d9 c0 c9 03 f6 d1 32 cb f6 d1 80 e9 03 80 f1 8a c0 c1 02 80 f1 33 f6 d1 80 e9 39 d0 c1 2a cb 32 cb 80 c1 59 f6 d1 2a cb 32 cb f6 d9 80 f1 b7 2a c1 f6 d0 2c 55 f6 d0 2c 5e 34 88 2a c3 34 9b 02 c3 c0 c8 03 02 c3 88 04 13 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}