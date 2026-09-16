rule Trojan_Win32_BunituCrypt_RT_MTB_15{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-05] 0e 00 00 00 } 		$a_03_1 = {31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 ?? 8b 45 ?? 03 45 ?? 2d 00 10 00 00 83 c0 04 } 		$a_03_2 = {31 18 83 45 ?? 04 83 45 ?? 04 8b [0-05] 3b [0-05] 0f [0-19] 2d 00 10 00 00 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}