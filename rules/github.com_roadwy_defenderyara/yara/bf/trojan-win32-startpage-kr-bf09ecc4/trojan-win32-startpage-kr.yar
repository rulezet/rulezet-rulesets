rule Trojan_Win32_Startpage_KR{
	meta:
		description = "Trojan:Win32/Startpage.KR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {60 9c 8b ca e8 00 00 00 00 5b 8d 55 bc b8 ?? ?? ?? ?? 52 ff d0 89 45 fc 9d 61 80 7d fc 00 74 06 0f b6 45 fc eb } 		$a_01_1 = {8a 04 16 8a c8 c0 e9 04 c0 e0 04 0a c8 80 7d ff 00 75 04 c6 45 ff 01 8a 45 ff } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}