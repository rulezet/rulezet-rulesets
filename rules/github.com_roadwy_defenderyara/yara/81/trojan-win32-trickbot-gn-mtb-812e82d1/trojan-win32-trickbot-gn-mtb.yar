rule Trojan_Win32_TrickBot_GN_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 83 c0 ?? 89 45 fc 8b 4d fc 3b 4d 10 74 ?? 8b 45 fc 33 d2 f7 75 14 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 11 8b 4d 0c 03 4d fc 88 01 eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}