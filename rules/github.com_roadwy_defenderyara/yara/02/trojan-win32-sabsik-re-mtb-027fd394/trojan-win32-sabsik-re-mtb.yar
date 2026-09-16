rule Trojan_Win32_Sabsik_RE_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ed 6b b1 55 b0 61 84 f5 36 14 18 29 7a d1 11 0d 98 88 6a ab bd c9 62 5c a0 eb e4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}