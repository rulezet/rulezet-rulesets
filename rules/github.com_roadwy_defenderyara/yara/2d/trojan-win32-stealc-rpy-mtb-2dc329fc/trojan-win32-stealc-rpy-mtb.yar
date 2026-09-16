rule Trojan_Win32_Stealc_RPY_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 60 31 ca a6 76 ed } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}