rule Trojan_Win32_Urelas_A{
	meta:
		description = "Trojan:Win32/Urelas.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 a4 1c 04 10 8d 55 ec 52 e8 00 dd fc ff 83 c4 10 c6 45 fc 00 8d 4d e8 e8 81 de fc ff 51 8b c4 89 65 e4 50 e8 55 03 00 00 83 c4 04 89 45 d4 8b 4d d4 89 4d d0 c6 45 fc 02 51 8b cc 89 65 e0 8d 55 ec 52 e8 16 d9 fc ff 89 45 cc c6 45 fc 00 e8 8a fd ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}