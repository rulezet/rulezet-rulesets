rule Trojan_Win32_Qbot_RPY_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b fe 46 3b f0 72 f2 85 ff 74 18 8b 4d fc 8b d7 2b d9 66 8b 04 0b 66 89 01 8d 49 02 83 ef 01 75 f1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}