rule Trojan_Win32_SmokeLoader_RG_MTB_4{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf c1 e9 05 03 4c 24 ?? 8b d7 c1 e2 04 03 54 24 ?? 8d 04 2f 33 ca 33 c8 2b d9 8b cb c1 e1 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}