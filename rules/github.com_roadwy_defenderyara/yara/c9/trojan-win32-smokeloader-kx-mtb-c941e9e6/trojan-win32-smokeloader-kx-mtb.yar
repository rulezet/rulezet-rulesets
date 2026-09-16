rule Trojan_Win32_SmokeLoader_KX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 dc 59 e8 00 00 00 00 75 05 74 03 33 70 b9 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}