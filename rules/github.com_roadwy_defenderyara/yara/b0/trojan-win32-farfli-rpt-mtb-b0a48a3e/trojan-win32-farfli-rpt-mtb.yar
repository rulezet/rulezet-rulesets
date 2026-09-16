rule Trojan_Win32_Farfli_RPT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 0c 06 8b 44 24 1c 0f be 04 07 99 f7 fb 8b c6 80 c2 4f 30 11 59 99 f7 f9 47 85 d2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}