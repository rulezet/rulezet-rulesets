rule Trojan_Win32_Raccrypt_GN_MTB_9{
	meta:
		description = "Trojan:Win32/Raccrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 01 45 fc 8b 45 fc 33 45 08 c9 c2 08 00 81 00 f5 34 ef c6 c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}