rule Trojan_Win32_Raccoon_RG_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}