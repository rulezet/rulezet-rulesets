rule Trojan_Win32_Raccoon_RK_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c 01 45 08 8b 45 0c 01 01 5d c2 08 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}