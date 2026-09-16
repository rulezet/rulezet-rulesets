rule Trojan_Win32_RedLine_RDCN_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 3e 8b c6 f7 74 24 18 6a 00 6a 00 8a 82 ?? ?? ?? ?? 32 c3 02 c3 88 04 3e } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}