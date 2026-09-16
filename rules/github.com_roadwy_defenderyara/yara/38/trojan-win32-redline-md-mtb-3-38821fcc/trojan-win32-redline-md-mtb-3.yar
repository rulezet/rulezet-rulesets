rule Trojan_Win32_Redline_MD_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 29 c8 88 84 24 97 01 00 00 0f b6 84 24 97 01 00 00 83 e8 24 88 84 24 97 01 00 00 8b 8c 24 98 01 00 00 0f b6 84 24 97 01 00 00 31 c8 88 84 24 97 01 00 00 0f b6 84 24 97 01 00 00 83 f0 ff 88 84 24 97 01 00 00 0f b6 8c 24 97 01 00 00 31 c0 29 c8 88 84 24 97 01 00 00 8a 8c 24 97 01 00 00 8b 84 24 98 01 00 00 88 8c 04 9d 01 00 00 8b 84 24 98 01 00 00 83 c0 01 89 84 24 98 01 00 00 e9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}