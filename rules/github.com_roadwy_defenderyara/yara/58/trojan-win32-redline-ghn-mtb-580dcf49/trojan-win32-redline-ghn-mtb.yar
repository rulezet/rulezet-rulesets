rule Trojan_Win32_Redline_GHN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 4c 1d 10 88 4c 3d 10 88 54 1d 10 0f b6 4c 3d 10 03 ce 0f b6 c9 c7 45 ?? ?? ?? ?? ?? 8a 4c 0d ?? 32 88 ?? ?? ?? ?? 88 88 ?? ?? ?? ?? c7 45 fc ?? ?? ?? ?? 40 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}