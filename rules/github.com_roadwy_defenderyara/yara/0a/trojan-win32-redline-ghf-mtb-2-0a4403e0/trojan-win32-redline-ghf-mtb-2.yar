rule Trojan_Win32_Redline_GHF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 ?? 0f be 4d ?? 0f be 75 ?? 8b 45 ?? 99 bf ?? ?? ?? ?? f7 ff 8b 45 ?? 0f be 14 10 69 d2 ?? ?? ?? ?? 33 f2 03 ce 8b 45 ?? 03 45 ?? 88 08 0f be 4d ?? 8b 55 ?? 03 55 ?? 0f b6 02 2b c1 8b 4d ?? 03 4d ?? 88 01 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}