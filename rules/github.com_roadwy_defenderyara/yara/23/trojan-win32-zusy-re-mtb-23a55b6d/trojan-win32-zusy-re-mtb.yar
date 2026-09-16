rule Trojan_Win32_Zusy_RE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 6a 37 5e f7 f6 83 c2 32 66 31 54 4d ac 41 83 f9 17 7c e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}