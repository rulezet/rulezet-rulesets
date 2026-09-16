rule Trojan_Win32_Azorult_CB_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 59 85 c0 75 17 8b 45 fc 8b 4d e8 0f b7 04 41 8b 4d e4 8b 55 08 03 14 81 8b c2 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}