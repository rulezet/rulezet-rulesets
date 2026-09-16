rule Trojan_Win32_Zbot_BAG_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 90 48 90 90 90 a1 70 50 40 00 30 10 ba 74 50 40 00 ff 0a b8 70 50 40 00 ff 00 eb } 		$a_01_1 = {b9 1a 00 00 56 0f a2 0f 31 89 c6 0f a2 0f 31 29 f0 89 45 f4 5e 81 7d f4 00 01 00 00 7f } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}