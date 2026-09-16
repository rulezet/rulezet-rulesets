rule Trojan_Win32_Farfli_RPT_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 8c 55 f4 fd ff ff 83 f9 3b 74 08 83 f9 64 74 03 83 f1 1b 66 89 8c 55 ec fb ff ff 42 3b d0 7c de } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}