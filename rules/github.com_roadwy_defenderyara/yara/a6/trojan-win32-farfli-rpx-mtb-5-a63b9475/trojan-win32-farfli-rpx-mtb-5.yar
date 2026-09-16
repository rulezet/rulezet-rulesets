rule Trojan_Win32_Farfli_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d8 89 5c 24 50 85 db 74 78 33 c0 80 34 30 63 40 3d 8c 03 00 00 72 f4 8d 44 24 14 50 6a 00 6a 00 56 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}