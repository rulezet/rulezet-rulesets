rule Trojan_Win32_Redline_MF_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b 75 d4 28 01 f2 03 4a 14 8b 55 dc 8b 75 d8 6b 7d d4 28 01 fe 03 56 0c 89 14 24 89 4c 24 04 89 44 24 08 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}