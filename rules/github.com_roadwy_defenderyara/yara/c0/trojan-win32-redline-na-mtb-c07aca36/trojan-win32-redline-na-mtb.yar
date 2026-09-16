rule Trojan_Win32_Redline_NA_MTB{
	meta:
		description = "Trojan:Win32/Redline.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 f7 75 08 83 c7 ?? 0f b6 04 1a 33 d2 30 06 8d 04 31 f7 75 08 8d 76 02 0f b6 04 1a 30 46 ff 83 ff } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}