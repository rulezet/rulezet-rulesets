rule Trojan_Win32_Farfli_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c0 31 37 01 db 81 c7 01 00 00 00 39 d7 75 e0 21 d8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}