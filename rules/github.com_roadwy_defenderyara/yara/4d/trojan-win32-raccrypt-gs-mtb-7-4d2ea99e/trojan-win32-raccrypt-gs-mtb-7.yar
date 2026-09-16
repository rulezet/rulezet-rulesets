rule Trojan_Win32_Raccrypt_GS_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 45 08 8b 45 08 c9 c2 08 00 81 00 eb 34 ef c6 c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}