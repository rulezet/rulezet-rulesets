rule Trojan_Win32_Qbot_PAF_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}