rule Trojan_Win32_Zusy_RD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 65 00 88 07 00 e0 0f b6 f8 8b 44 24 14 8a 00 43 32 04 37 8b 3c 24 ff 44 24 14 47 88 43 ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}