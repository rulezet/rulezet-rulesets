rule Trojan_Win32_CobaltStrike_MP_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 18 8b 4c 24 14 83 c7 14 41 89 7c 24 18 3b 4c 24 24 89 4c 24 14 8b 4c 24 28 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}