rule Trojan_Win32_Redline_MO_MTB{
	meta:
		description = "Trojan:Win32/Redline.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 44 2c 3c 0f b6 44 1c 3c 03 44 24 34 0f b6 c0 8a 44 04 3c 30 04 39 8b 44 24 14 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}