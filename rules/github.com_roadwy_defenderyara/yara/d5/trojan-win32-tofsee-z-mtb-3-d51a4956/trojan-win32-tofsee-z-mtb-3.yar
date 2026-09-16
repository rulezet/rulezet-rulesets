rule Trojan_Win32_Tofsee_Z_MTB_3{
	meta:
		description = "Trojan:Win32/Tofsee.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 53 8a 18 84 db 74 2d 8b d0 2b 54 24 0c 8b 4c 24 0c 84 db 74 12 8a 19 84 db 74 1b 38 1c 0a 75 07 41 80 3c 0a 00 75 ee 80 39 00 74 0a 40 8a 18 42 84 db 75 d9 33 c0 5b c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}