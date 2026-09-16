rule Trojan_Win32_DarkComet_ADK_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 34 00 01 31 00 00 02 31 36 00 01 32 00 00 01 38 00 00 01 33 00 00 01 34 00 00 03 31 32 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}