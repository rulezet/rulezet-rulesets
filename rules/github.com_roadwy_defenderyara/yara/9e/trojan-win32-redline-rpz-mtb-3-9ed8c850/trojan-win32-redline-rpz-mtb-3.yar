rule Trojan_Win32_Redline_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 ff 83 e0 4a 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 8b 4d 0c 03 4d fc 0f b6 11 2b d0 8b 45 0c 03 45 fc 88 10 eb 83 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}