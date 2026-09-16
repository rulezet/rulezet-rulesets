rule Trojan_Win32_Staser_RE_MTB{
	meta:
		description = "Trojan:Win32/Staser.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 03 33 c0 33 db 90 59 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}