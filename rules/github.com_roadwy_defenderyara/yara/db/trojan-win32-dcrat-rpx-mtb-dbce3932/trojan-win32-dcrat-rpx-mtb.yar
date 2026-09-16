rule Trojan_Win32_DCRat_RPX_MTB{
	meta:
		description = "Trojan:Win32/DCRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d ec aa fe ff 83 c1 01 89 8d ec aa fe ff 8b 95 ec aa fe ff 3b 95 f4 aa fe ff 73 29 8b 85 ec aa fe ff c1 e0 00 8d 8d f8 aa fe ff 0f b6 14 08 f7 da 8b 85 ec aa fe ff c1 e0 00 8d 8d f8 aa fe ff 88 14 08 eb ba } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}