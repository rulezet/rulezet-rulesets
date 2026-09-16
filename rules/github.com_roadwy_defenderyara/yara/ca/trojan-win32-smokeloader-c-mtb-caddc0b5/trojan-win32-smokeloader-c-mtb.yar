rule Trojan_Win32_SmokeLoader_C_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 ea 03 c7 03 55 d8 33 d0 31 55 f8 8b 45 f8 29 45 ec 8b 45 e0 29 45 f4 ff 4d e4 0f 85 f2 fe ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}