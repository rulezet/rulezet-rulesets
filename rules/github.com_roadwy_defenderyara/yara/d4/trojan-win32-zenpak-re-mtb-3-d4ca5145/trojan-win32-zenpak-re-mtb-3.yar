rule Trojan_Win32_Zenpak_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 03 8d 05 ?? ?? ?? ?? 31 18 40 40 83 f0 03 8d 05 ?? ?? ?? ?? 01 30 ba 05 00 00 00 83 f0 04 31 d0 8d 05 ?? ?? ?? ?? 89 38 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}