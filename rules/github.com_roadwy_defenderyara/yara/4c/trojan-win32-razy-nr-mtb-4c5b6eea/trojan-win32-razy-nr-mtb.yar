rule Trojan_Win32_Razy_NR_MTB{
	meta:
		description = "Trojan:Win32/Razy.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 00 00 00 83 ec ?? 75 05 74 03 33 bd ?? ?? ?? ?? 83 c4 04 eb 06 4c 29 c0 eb 05 2a eb } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}