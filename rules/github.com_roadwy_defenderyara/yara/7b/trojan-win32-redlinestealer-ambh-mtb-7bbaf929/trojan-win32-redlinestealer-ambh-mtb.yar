rule Trojan_Win32_RedlineStealer_AMBH_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d8 88 45 db 0f b6 4d db 03 4d dc 88 4d db 0f b6 55 db f7 d2 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}