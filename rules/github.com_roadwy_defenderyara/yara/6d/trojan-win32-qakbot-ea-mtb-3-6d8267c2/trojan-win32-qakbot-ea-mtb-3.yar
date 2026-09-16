rule Trojan_Win32_Qakbot_EA_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a c8 c0 e1 02 8a c4 c0 eb 04 80 e3 03 c0 e0 04 02 d9 8a ca c0 e9 02 80 e1 0f c0 e2 06 02 55 ff 02 c8 8b 45 f0 88 4d 09 88 5d 08 88 55 0a 88 48 ff 8b 4d f8 88 58 fe } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}