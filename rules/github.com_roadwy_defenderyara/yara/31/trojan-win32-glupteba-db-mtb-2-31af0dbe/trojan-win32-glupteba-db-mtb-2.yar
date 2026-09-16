rule Trojan_Win32_Glupteba_DB_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 4c 8b f0 83 64 24 ?? ?? d3 e6 03 74 24 ?? 81 6c 24 ?? aa a0 5b 7e 81 44 24 ?? 62 7e e6 6f 81 44 24 ?? 4d 22 75 0e 8b 4c 24 ?? 8b d0 8b 5c 24 ?? 03 c3 d3 ea 03 54 24 ?? 33 d0 33 d6 2b fa 81 3d ?? ?? ?? ?? fd 13 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}