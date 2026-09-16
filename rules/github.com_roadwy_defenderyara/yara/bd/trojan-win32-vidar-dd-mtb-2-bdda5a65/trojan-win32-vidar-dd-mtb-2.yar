rule Trojan_Win32_Vidar_DD_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c8 88 45 ?? 0f b6 45 ?? 0f b6 84 05 ?? ?? ?? ?? 88 45 ?? 8b 55 ?? 8b 45 ?? 01 d0 0f b6 00 32 45 ?? 88 45 ?? 8b 55 ?? 8b 45 ?? 01 c2 0f b6 45 ?? 88 02 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}