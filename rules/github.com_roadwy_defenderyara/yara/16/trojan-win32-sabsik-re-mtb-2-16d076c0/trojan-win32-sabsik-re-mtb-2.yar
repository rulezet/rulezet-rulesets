rule Trojan_Win32_Sabsik_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Sabsik.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 16 8b c2 8b cb d3 e8 8b 4d 08 d3 e2 4f 8d 76 04 0b 55 fc 89 00 fc 89 56 fc 85 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}