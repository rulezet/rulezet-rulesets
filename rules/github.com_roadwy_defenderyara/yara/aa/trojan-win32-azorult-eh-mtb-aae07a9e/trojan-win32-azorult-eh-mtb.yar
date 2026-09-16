rule Trojan_Win32_Azorult_EH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 02 00 00 00 8b 45 0c 90 01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}