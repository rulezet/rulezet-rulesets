rule Trojan_Win32_Qakbot_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 89 4d fc 8b 45 fc 89 45 f8 6b 45 08 18 8b 4d f8 03 01 8b e5 5d } 		$a_01_1 = {64 65 73 6b 74 6f 70 2e 64 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}