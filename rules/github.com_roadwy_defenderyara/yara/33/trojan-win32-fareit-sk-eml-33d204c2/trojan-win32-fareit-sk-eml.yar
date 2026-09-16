rule Trojan_Win32_Fareit_SK_eml{
	meta:
		description = "Trojan:Win32/Fareit.SK!eml,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8d 14 03 80 32 30 40 3d 09 5c 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}