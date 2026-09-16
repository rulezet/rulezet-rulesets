rule Trojan_Win32_Redline_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d db 0f b6 45 db 2d c2 00 00 00 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db 03 55 dc 88 55 db 0f b6 45 db f7 d0 88 45 db 0f b6 4d db 81 e9 a3 00 00 00 88 4d db 8b 55 dc 8a 45 db 88 44 15 e8 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}