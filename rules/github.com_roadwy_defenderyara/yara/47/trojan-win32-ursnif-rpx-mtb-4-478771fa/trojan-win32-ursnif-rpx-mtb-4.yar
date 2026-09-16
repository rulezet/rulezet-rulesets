rule Trojan_Win32_UrSnif_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 db 0f 84 50 00 00 00 56 89 2c 24 89 14 24 68 00 00 00 00 5a 01 c2 50 b8 00 00 00 00 01 d0 01 08 58 5a 83 ec 04 89 14 24 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}