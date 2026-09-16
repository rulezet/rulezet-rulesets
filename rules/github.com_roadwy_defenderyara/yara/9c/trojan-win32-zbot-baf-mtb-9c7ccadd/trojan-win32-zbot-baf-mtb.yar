rule Trojan_Win32_Zbot_BAF_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 02 83 c2 04 f7 d8 8d 40 d7 83 e8 02 83 c0 01 29 d8 89 c3 6a 00 8f 07 01 47 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}