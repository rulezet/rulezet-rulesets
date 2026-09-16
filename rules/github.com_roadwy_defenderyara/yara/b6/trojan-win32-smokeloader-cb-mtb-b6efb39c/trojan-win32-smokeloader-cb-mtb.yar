rule Trojan_Win32_SmokeLoader_CB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 78 8b 4d 7c 31 08 83 c5 70 c9 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 01 45 08 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}