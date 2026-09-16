rule Trojan_Win32_Trickbot_BZ_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.BZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0e 8b c3 8b 51 0c 8b 59 14 2b d3 03 d7 66 0f b6 0a 8b d9 2b c8 66 85 c9 7d 06 81 c1 00 01 00 00 8b 85 30 ff ff ff 88 0a 03 f8 eb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}