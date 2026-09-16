rule Trojan_Win32_QakBot_RPB_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b 4c 24 ?? 8a 14 01 8b 74 24 ?? 88 14 06 83 c0 01 8b 7c 24 ?? 39 f8 89 04 24 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}