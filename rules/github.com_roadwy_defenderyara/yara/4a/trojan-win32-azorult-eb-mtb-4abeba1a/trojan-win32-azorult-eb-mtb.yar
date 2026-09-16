rule Trojan_Win32_Azorult_EB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01 c9 c2 08 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}