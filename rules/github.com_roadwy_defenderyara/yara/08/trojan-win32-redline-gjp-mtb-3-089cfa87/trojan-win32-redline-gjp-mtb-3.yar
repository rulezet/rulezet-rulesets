rule Trojan_Win32_Redline_GJP_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 89 c1 8b 55 ec 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 ec } 		$a_03_1 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 01 c0 01 d0 89 c1 8b 55 ec 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 ec } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}