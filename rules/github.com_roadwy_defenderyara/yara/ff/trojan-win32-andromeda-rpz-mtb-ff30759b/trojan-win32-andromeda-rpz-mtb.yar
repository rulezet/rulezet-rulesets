rule Trojan_Win32_Andromeda_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Andromeda.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 8b 51 54 52 8b 45 08 8b 48 0c 51 8b 55 d0 52 8b 45 d8 50 8b 4d 08 8b 91 80 00 00 00 ff d2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}