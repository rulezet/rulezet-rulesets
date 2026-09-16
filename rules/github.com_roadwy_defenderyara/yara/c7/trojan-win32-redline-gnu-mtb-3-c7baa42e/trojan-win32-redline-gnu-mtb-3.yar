rule Trojan_Win32_Redline_GNU_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 f0 56 57 e8 ?? ?? ?? ?? 0f b6 06 83 c4 ?? 0f b6 0f 03 c8 0f b6 c1 8b 4c 24 ?? 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}