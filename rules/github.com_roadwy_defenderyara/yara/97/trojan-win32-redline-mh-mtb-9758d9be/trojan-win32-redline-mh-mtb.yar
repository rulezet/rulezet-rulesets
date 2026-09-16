rule Trojan_Win32_Redline_MH_MTB{
	meta:
		description = "Trojan:Win32/Redline.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b ca 8b c6 33 d2 f7 f1 8a 04 3a 30 04 2e 46 3b f3 7c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}