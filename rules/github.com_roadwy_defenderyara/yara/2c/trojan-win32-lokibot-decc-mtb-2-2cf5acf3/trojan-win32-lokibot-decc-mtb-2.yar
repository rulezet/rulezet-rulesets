rule Trojan_Win32_Lokibot_DECC_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.DECC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca d1 e8 c1 e1 07 46 0b c8 03 cf 03 d1 0f be 3e 8b c2 85 ff 75 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}