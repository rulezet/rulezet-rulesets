rule Trojan_Win32_FlyStudio_AFY_MTB_2{
	meta:
		description = "Trojan:Win32/FlyStudio.AFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 51 68 c0 5c 4e 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 83 fe 20 0f 87 e4 00 00 00 8d 54 24 14 8b cf 52 68 b8 5c 4e 00 68 00 00 00 80 e8 ?? ?? ?? ?? 85 c0 0f 85 c6 00 00 00 8b 1d 9c 62 4a 00 8d 44 24 14 68 a4 5c 4e 00 50 ff d3 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}