rule Trojan_Win32_SmokeLoader_GJV_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.GJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4d cc 8d 45 e4 89 5d f4 89 55 e4 e8 ?? ?? ?? ?? 8b 45 e4 33 c3 31 45 e0 89 35 ?? ?? ?? ?? 8b 45 e0 29 45 fc 81 45 ?? 47 86 c8 61 ff 4d dc 0f 85 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}