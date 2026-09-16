rule Trojan_Win32_Raccoon_RN_MTB_2{
	meta:
		description = "Trojan:Win32/Raccoon.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 [0-25] 55 8b ec 8b 45 0c 8b 4d 08 c1 e0 04 89 01 5d c2 08 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}