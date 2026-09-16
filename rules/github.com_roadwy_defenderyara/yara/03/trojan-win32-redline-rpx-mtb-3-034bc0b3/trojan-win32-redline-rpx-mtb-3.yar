rule Trojan_Win32_RedLine_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 55 d4 52 6a 40 8b 45 cc 50 68 ?? ?? ?? ?? ff 55 e8 89 45 d0 } 		$a_03_1 = {8b 7d 08 33 db f6 17 80 37 ?? 47 e2 f6 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}