rule Trojan_Win32_Raccoon_RD_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}