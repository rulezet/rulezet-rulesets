rule Trojan_Win32_Redline_DF_MTB{
	meta:
		description = "Trojan:Win32/Redline.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 db 0f b6 4d db 2b 4d dc 88 4d db 0f b6 55 db c1 fa 02 0f b6 45 db c1 e0 06 0b d0 88 55 db 0f b6 4d db 81 e9 8e 00 00 00 88 4d db 0f b6 55 db f7 da 88 55 db 0f b6 45 db f7 d0 88 45 db 8b 4d dc 8a 55 db 88 54 0d e8 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}