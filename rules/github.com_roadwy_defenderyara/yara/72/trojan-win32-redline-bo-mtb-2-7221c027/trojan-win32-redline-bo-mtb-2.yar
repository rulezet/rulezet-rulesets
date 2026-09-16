rule Trojan_Win32_Redline_BO_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 d1 88 4d ?? 8b 45 ?? 03 45 ?? 8a 08 88 4d ?? 0f b6 55 ?? 8b 45 ?? 03 45 ?? 0f b6 08 } 		$a_03_1 = {03 ca 8b 55 ?? 03 55 ?? 88 0a 8a 45 ?? 88 45 ?? 0f b6 4d ?? 8b 55 ?? 03 55 ?? 0f b6 02 2b c1 8b 4d ?? 03 4d ?? 88 01 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}