rule Trojan_Win32_Redline_GAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 89 54 24 1c 8b c1 c1 e8 18 33 c1 69 c8 ?? ?? ?? ?? 69 c7 ?? ?? ?? ?? 33 c8 8b 44 24 2c 8b f9 3b d0 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}