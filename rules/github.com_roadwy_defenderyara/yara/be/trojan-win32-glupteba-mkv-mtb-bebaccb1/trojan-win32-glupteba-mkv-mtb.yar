rule Trojan_Win32_Glupteba_MKV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ee 03 74 24 ?? 8b 44 24 ?? 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 53 53 53 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 c6 89 44 24 10 2b f8 8b 44 24 38 29 44 24 14 83 6c 24 ?? ?? 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}