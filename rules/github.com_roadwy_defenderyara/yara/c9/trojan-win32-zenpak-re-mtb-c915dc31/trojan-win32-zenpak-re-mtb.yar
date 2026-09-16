rule Trojan_Win32_Zenpak_RE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f0 07 31 35 ?? ?? ?? ?? 4a 89 d0 42 8d 05 ?? ?? ?? ?? 89 38 8d 05 ?? ?? ?? ?? 01 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}