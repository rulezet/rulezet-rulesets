rule Trojan_Win32_Qbot_RPV_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RPV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 00 0f 47 00 8b 15 b0 0e 47 00 01 02 a1 e8 0e 47 00 2d a2 d1 00 00 03 05 00 0f 47 00 a3 f0 0e 47 00 a1 f0 0e 47 00 a3 ec 0e 47 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}