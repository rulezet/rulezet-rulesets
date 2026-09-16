rule Trojan_Win32_Redline_MKU_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 08 0f be 4d ?? 31 c8 0f be 4d ?? 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f be 14 08 29 f2 88 14 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}