rule Trojan_Win32_Zbot_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 d2 74 01 ?? 31 1f 81 c7 04 00 00 00 81 c1 ?? ?? ?? ?? 21 f6 39 d7 75 e7 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}