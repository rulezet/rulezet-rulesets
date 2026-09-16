rule Trojan_Win32_BunituCrypt_RT_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 5d ?? 8b 45 ?? 8b 55 ?? 89 10 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}