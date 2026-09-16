rule Trojan_Win32_Zbot_BAG_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 33 d2 b9 00 01 00 00 f7 f1 89 95 e8 fb ff ff 8b 95 e8 fb ff ff 8a 84 15 e4 fa ff ff 88 85 c0 f7 ff ff 8b 0d [0-04] 03 8d d0 f8 ff ff 0f be 11 0f be 85 c0 f7 ff ff 33 d0 8b 0d [0-04] 03 8d d0 f8 ff ff 88 11 e9 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}