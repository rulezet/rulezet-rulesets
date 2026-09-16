rule Trojan_Win32_DarkComet_ADK_MTB_3{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 6a 00 53 68 4c 28 1c 13 6a 00 6a 00 e8 dd 4f f8 ff db 6d e8 d8 25 24 2b 1c 13 db 7d e8 9b db 6d e8 d8 1d 1c 2b 1c 13 9b df e0 9e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}