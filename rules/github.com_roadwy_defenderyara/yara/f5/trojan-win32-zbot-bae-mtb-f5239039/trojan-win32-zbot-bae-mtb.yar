rule Trojan_Win32_Zbot_BAE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 40 d4 c1 c8 08 29 f8 83 e8 01 31 ff 4f 21 c7 c1 c7 08 89 03 83 eb fc 83 c6 fc } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}