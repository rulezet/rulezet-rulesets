rule Trojan_Win32_Dridex_DB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d9 03 1d ?? ?? ?? ?? 0f b7 d0 03 d3 89 15 ?? ?? ?? ?? 2a d0 80 c2 35 02 d2 02 ca 8a d0 2a 15 ?? ?? ?? ?? 81 c7 6c 2b 06 01 80 ea 4b 89 3d ?? ?? ?? ?? 89 bc 2e a3 f0 ff ff 02 ca 8b 15 ?? ?? ?? ?? 83 c6 04 81 fe 6d 10 00 00 0f 82 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}