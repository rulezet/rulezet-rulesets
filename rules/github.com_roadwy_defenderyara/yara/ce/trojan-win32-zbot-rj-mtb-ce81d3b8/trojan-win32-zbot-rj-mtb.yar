rule Trojan_Win32_Zbot_RJ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 cf 87 da 01 75 c0 03 4d a0 4a 89 75 b8 2b ce 99 33 d6 03 ce 03 d2 87 ca 2b d9 03 4d c0 89 6d f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}