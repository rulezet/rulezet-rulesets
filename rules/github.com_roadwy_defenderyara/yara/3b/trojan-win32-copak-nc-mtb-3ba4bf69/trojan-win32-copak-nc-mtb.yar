rule Trojan_Win32_Copak_NC_MTB{
	meta:
		description = "Trojan:Win32/Copak.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 4b 8b 3c 24 83 c4 04 81 ea ?? ?? ?? ?? 21 db 8b 34 24 } 		$a_03_1 = {83 c4 04 e8 28 00 00 00 09 db 89 ca 8b 3c 24 83 c4 ?? 81 eb 01 00 00 00 5e 09 d3 21 db } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}