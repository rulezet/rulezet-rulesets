rule Trojan_Win32_RedLine_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c1 cf 51 c1 ea ba 66 81 c3 8d 01 c1 d6 7a 42 66 0b c7 c1 d0 22 66 0d e8 01 66 4e 66 f7 ea c1 d1 fd 66 c1 db 79 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}