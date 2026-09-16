rule Trojan_Win32_Gozi_RE_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 45 fc 0f b6 08 8b 45 fc 99 be 34 00 00 00 f7 fe 8b 45 f4 0f b6 14 10 33 ca 8b 45 f8 03 45 fc 88 08 eb c8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}