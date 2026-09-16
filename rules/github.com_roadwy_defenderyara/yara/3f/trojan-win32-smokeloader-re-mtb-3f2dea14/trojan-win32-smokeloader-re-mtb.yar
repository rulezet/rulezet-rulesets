rule Trojan_Win32_SmokeLoader_RE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 ab 0f 1b 81 6c 24 ?? 8d 1f 25 59 81 ac 24 ?? 00 00 00 e0 02 53 2c 81 ?? 24 [0-04] f0 b0 7d 6d 81 84 24 ?? 00 00 00 40 c1 58 20 81 44 24 ?? f0 98 30 35 b8 8c 6d 49 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}