rule Trojan_Win32_Lazy_NL_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 f9 80 3e 00 75 ec 83 7c 24 ?? 01 75 63 eb 03 8d 49 00 8a 07 88 06 8a 0f 46 47 } 		$a_01_1 = {8d 9b 00 00 00 00 57 56 ff d3 85 c0 74 30 8a 06 46 84 c0 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}