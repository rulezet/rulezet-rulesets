rule Trojan_Win32_Qbot_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 a4 8b 45 d8 8b 55 a8 01 10 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 ?? ?? ?? ?? 03 45 a0 40 8b 55 d8 33 02 89 45 a0 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}