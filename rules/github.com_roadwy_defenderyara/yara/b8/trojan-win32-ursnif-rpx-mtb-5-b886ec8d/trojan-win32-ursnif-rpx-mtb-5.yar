rule Trojan_Win32_UrSnif_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/UrSnif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 0d 8b 54 24 44 8b 44 24 1c 88 1c 02 eb 0b 8b 44 24 44 8b 4c 24 1c 88 04 08 } 		$a_01_1 = {8b 54 24 4c 52 68 00 30 00 00 68 00 d0 02 00 56 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}