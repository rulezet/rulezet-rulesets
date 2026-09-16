rule Trojan_Win32_Redline_GNH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 6a } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}