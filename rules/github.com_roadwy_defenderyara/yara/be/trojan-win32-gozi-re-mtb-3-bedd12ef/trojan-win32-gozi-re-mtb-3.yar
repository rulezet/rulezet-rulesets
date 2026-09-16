rule Trojan_Win32_Gozi_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0b 2b 4d 0c 89 45 f8 8b c2 c1 f8 1f 83 c8 ff 2b 45 0c 83 c7 04 83 c3 04 [0-08] 3b c8 76 09 c7 45 0c 01 00 00 00 eb 04 83 65 0c 00 8b 4d f8 29 0e 8b 06 83 ca ff 2b d1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}