rule Trojan_Win32_Zenpak_RE_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 1e 8b 7d e4 8b 5d d0 32 0c 1f 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 32 28 00 00 8b 55 e0 88 0c 1a c7 05 ?? ?? ?? ?? f4 04 00 00 8b 4d cc 8b 55 f0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}