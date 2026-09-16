rule Trojan_Win32_Redline_GND_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d0 88 45 db 0f b6 4d db 2b 4d dc 88 4d db 0f b6 55 db f7 d2 88 55 db 0f b6 45 db 83 e8 5e 88 45 db 0f b6 4d db f7 d1 88 4d db 0f b6 55 db 83 c2 20 88 55 db 8b 45 dc 8a 4d db 88 4c 05 e8 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}