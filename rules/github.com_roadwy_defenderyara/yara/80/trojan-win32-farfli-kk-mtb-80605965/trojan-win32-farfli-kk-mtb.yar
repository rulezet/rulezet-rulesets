rule Trojan_Win32_Farfli_KK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 85 30 fe ff ff 50 ff d7 8d 85 30 fe ff ff 50 ff d3 6a 00 6a 00 6a 00 8d 85 30 fe ff ff 50 ff d6 85 c0 } 	condition:
		((#a_01_0  & 1)*20) >=20
 
}