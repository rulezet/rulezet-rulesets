rule Trojan_Win32_Redline_RPZ_MTB_5{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 ca 88 4d ff 8b 45 0c 03 45 f8 8a 08 88 4d fd 0f b6 55 ff 8b 45 0c 03 45 f8 0f b6 08 03 ca 8b 55 0c 03 55 f8 88 0a 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 0c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}