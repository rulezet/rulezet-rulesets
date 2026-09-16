rule Trojan_Win32_BunituCrypt_RT_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 7c 30 00 00 03 45 ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 6a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}