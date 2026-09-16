rule Trojan_Win32_Farfli_RPZ_MTB_4{
	meta:
		description = "Trojan:Win32/Farfli.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 11 02 d0 32 d0 02 d0 32 d0 88 11 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}