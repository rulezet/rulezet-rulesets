rule Trojan_Win32_Gozi_GR_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2a d9 80 c3 ?? 02 c3 66 0f b6 c8 66 03 ca 8b 16 81 c2 ?? ?? ?? ?? 66 83 c1 ?? 89 16 0f b7 c9 89 15 ?? ?? ?? ?? 8a d1 2a 15 ?? ?? ?? ?? 83 c6 04 80 c2 ?? 02 c2 83 ed 01 8b 15 ?? ?? ?? ?? 75 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}