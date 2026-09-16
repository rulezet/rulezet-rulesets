rule Trojan_Win32_Raccoon_RI_MTB_3{
	meta:
		description = "Trojan:Win32/Raccoon.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 c2 08 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}