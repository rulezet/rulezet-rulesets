rule Trojan_Win32_Redline_MH_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 6c 24 10 c7 44 24 18 00 00 00 00 8b 44 24 24 01 44 24 18 8b 44 24 28 90 01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6 } 		$a_03_1 = {d3 e8 8b 4c 24 10 03 44 24 30 89 44 24 14 33 44 24 20 33 c8 2b f9 8d 44 24 24 89 4c 24 10 89 7c 24 28 e8 ?? ?? ?? ?? 83 eb 01 0f 85 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}