rule Trojan_Win32_ICLoader_RD_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 57 8b 3d 78 01 65 00 68 7c 32 65 00 ff d7 8b 35 74 01 65 00 a3 70 41 a5 00 85 c0 0f 84 ff 00 00 00 68 64 32 65 00 50 ff d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}