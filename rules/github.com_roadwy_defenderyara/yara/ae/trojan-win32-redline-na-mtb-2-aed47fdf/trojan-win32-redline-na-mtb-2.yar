rule Trojan_Win32_Redline_NA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 31 08 5d } 		$a_03_1 = {8b c1 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 ?? 33 f8 89 7d ?? 8b 45 ?? 29 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 2b 5d ?? ff 4d ?? 89 5d ?? 0f 85 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}