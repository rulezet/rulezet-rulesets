rule Trojan_Win32_UrSnif_RPH_MTB_2{
	meta:
		description = "Trojan:Win32/UrSnif.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 fc 0f be 02 89 45 f8 8b 4d 08 03 4d fc 51 } 		$a_03_1 = {55 8b ec 53 8b 45 08 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 4d 08 88 19 5b 5d c2 04 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}