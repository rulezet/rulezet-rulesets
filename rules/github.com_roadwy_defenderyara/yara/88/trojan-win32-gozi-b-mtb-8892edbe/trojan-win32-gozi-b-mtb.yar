rule Trojan_Win32_Gozi_B_MTB{
	meta:
		description = "Trojan:Win32/Gozi.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 ca 58 55 00 00 0f b7 d1 0f b7 f2 81 c7 08 1a 03 01 2b f0 8b 44 24 18 83 ee 07 89 38 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}