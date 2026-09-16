rule Trojan_Win32_Razy_PGR_MTB{
	meta:
		description = "Trojan:Win32/Razy.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 59 09 f6 ?? ?? ?? ?? ?? 31 10 81 c0 ?? ?? ?? ?? 46 39 d8 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}