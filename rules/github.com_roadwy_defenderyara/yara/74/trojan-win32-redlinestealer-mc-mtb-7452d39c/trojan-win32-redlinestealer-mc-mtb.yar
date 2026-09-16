rule Trojan_Win32_RedLineStealer_MC_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 95 9c fd ff ff 83 c2 01 89 95 9c fd ff ff 83 bd 9c fd ff ff 0c 73 ?? 8b 85 9c fd ff ff 0f b6 4c 05 d0 81 c1 b5 00 00 00 8b 95 9c fd ff ff 88 4c 15 d0 eb ?? c6 45 cd 00 0f b6 45 d1 85 c0 74 } 		$a_01_1 = {55 6e 6c 6f 63 6b 46 69 6c 65 45 78 } 		$a_01_2 = {47 65 74 43 50 49 6e 66 6f 45 78 57 } 		$a_01_3 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 41 } 		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}