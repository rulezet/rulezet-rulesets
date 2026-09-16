rule Trojan_Win32_Ekstak_RE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 90 90 90 90 55 8b ec 8b 45 14 50 ff 15 e8 94 65 00 e9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}