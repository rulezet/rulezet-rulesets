rule Trojan_Win32_Amadey_AMD_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d0 8b 75 d4 8b 55 b0 8b 14 95 c8 e3 41 00 03 d1 8a 0c 03 03 d3 43 88 4c 32 2e 8b 4d bc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}