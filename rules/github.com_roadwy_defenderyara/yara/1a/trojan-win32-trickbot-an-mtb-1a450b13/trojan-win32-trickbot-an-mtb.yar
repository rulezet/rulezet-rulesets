rule Trojan_Win32_Trickbot_AN_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 09 89 4e 08 8b 54 3a fc 8b fa 2b f9 89 7e 0c 76 1b 33 ff 33 f6 46 83 ff ?? 7f 0b 8a 1c 38 03 fe 30 19 03 ce eb 02 33 ff 3b ca 72 ea 5f 5b 5e 33 c0 c2 04 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}