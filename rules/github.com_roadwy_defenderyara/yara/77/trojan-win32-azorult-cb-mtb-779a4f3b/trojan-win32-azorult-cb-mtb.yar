rule Trojan_Win32_Azorult_CB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 78 8b 4d 7c 31 08 83 c5 70 c9 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}