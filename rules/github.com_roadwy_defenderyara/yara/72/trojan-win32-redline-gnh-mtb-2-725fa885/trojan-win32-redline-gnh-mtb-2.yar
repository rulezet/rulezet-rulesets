rule Trojan_Win32_Redline_GNH_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 69 db ?? ?? ?? ?? 69 0c b8 ?? ?? ?? ?? 47 8b c1 c1 e8 18 33 c1 69 c8 ?? ?? ?? ?? 33 d9 3b fd 0f 8c } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}