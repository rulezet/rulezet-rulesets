rule Trojan_Win32_Azorult_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 04 00 00 00 8b 45 0c 83 6d fc 04 90 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}