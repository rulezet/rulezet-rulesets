rule Trojan_Win32_Doina_MX_MTB{
	meta:
		description = "Trojan:Win32/Doina.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 85 f8 fe ff ff 68 04 01 00 00 50 e8 32 bd 00 00 68 ff 03 00 00 8d 85 f9 fa ff ff c6 85 f8 fa ff ff 00 6a 00 50 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}