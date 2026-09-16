rule Trojan_Win32_Redline_GMZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 80 34 03 ?? ff d7 6a 00 ff d6 8b 44 24 ?? 6a 00 6a 00 80 34 03 ?? ff d7 6a 00 ff d6 8b 44 24 ?? 6a 00 6a 00 80 04 03 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}