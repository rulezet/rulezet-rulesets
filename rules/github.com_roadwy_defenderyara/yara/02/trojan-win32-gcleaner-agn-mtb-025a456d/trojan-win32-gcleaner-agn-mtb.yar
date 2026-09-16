rule Trojan_Win32_GCleaner_AGN_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 80 b0 a0 bb 42 00 2e 40 83 f8 0f 72 f3 b9 a0 bb 42 00 } 		$a_01_1 = {8b ec 83 ec 08 a1 18 a0 42 00 33 c5 89 45 fc 64 a1 2c 00 00 00 c7 45 f8 5a 59 41 2e 8b 08 a1 78 bc 42 00 3b 81 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}