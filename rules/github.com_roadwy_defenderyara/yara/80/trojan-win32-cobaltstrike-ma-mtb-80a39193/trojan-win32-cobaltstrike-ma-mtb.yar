rule Trojan_Win32_CobaltStrike_MA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc ?? 73 14 8b 4d fc 0f be 54 0d e0 83 f2 44 8b 45 fc 88 54 05 e0 eb dd } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}