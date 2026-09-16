rule Trojan_Win32_Zenpak_RA_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpak.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 8d 8d fc fe ff ff 81 c1 03 00 00 00 8a 95 ff fe ff ff 80 fa 4d 0f 94 c6 89 85 ?? fe ff ff 89 8d ?? fe ff ff 88 95 ?? fe ff ff 88 b5 ?? fe ff ff 8a 85 ?? fe ff ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}