rule Trojan_Win32_Redline_MF_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 0f be 34 10 8b 45 08 8b 4d f0 0f be 14 08 31 f2 88 14 08 8b 45 f0 83 c0 01 89 45 f0 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}