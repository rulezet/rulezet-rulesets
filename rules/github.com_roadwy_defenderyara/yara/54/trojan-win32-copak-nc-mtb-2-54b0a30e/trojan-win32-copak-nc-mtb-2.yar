rule Trojan_Win32_Copak_NC_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 3c 3b 8b 3f 21 c0 81 e7 ?? ?? ?? ?? 89 d0 43 42 21 c2 81 fb f4 01 00 00 75 05 } 		$a_03_1 = {81 ee 45 af a2 a7 81 c3 ?? ?? ?? ?? db 81 c1 01 00 00 00 21 db 89 db 81 f9 f4 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}