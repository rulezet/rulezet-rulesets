rule Trojan_Win32_Zenpak_RD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 e8 47 54 00 00 89 25 38 3e 43 00 89 2d 3c 3e 43 00 e8 99 53 00 00 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}