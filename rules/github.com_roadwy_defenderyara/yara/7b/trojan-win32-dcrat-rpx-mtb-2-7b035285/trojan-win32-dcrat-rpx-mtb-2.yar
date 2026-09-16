rule Trojan_Win32_DCRat_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/DCRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 85 f8 aa fe ff e8 c6 85 f9 aa fe ff 88 c6 85 fa aa fe ff f7 c6 85 fb aa fe ff 00 c6 85 fc aa fe ff 00 c6 85 fd aa fe ff 88 c6 85 fe aa fe ff f7 c6 85 ff aa fe ff 00 c6 85 00 ab fe ff 00 c6 85 01 ab fe ff 00 c6 85 02 ab fe ff 97 c6 85 03 ab fe ff f2 c6 85 04 ab fe ff a3 c6 85 05 ab fe ff 74 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}