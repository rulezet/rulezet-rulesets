rule Trojan_Win32_Raccoon_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 09 8b 85 ?? ?? ff ff 99 be 26 00 00 00 f7 fe 8b 85 ?? ?? ff ff 0f b6 14 10 33 ca 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 88 08 eb aa } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}