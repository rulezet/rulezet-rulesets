rule Trojan_Win32_Redline_MG_MTB{
	meta:
		description = "Trojan:Win32/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 8b 55 f4 8b 45 08 01 d0 0f b6 55 e7 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 0c 7c ac } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}