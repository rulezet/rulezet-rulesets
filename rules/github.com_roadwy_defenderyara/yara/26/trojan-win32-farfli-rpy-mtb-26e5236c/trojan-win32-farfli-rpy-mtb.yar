rule Trojan_Win32_Farfli_RPY_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 1e 29 c0 46 29 c0 47 39 ce 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}