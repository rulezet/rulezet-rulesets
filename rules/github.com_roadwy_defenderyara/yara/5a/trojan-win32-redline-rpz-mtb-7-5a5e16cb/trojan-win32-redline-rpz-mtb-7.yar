rule Trojan_Win32_Redline_RPZ_MTB_7{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 6a 40 8b 4d 0c 51 8b 55 08 52 ff 15 ?? ?? ?? 00 33 c0 33 d2 8b e5 5d c3 } 		$a_01_1 = {33 f0 03 ce 8b 55 0c 03 55 dc 88 0a 0f be 45 db 8b 4d 0c 03 4d dc 0f b6 11 2b d0 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}