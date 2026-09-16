rule Trojan_Win32_FormBook_AFK_MTB_4{
	meta:
		description = "Trojan:Win32/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c2 8b 4d fc 8b 51 60 8b 4d fc 8b 49 70 0f b6 14 11 03 c2 8b 4d fc 33 d2 f7 71 08 8b 45 fc 88 50 1c 8b 4d fc 8b 51 64 8b 45 fc 8b 48 60 8b 45 fc 8a 4c 0a 01 88 48 50 8b 55 fc 8b 42 64 8b 4d fc 0f b6 51 1c 8b 4d fc 8b 49 64 8b 75 fc 8b 76 60 8a 54 10 01 88 54 31 01 8b 45 fc 8b 48 64 8b 55 fc 0f b6 42 1c 8b 55 fc 8a 52 50 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}