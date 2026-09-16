rule Trojan_Win32_Raccoon_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 [0-25] 01 45 fc 8b 45 08 8b 4d ?? 31 08 c9 c2 08 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}