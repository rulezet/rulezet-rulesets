rule Trojan_Win32_ICLoader_GZF_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 cf c1 ca 00 00 ee 01 fb c1 ce ?? 01 e9 8b 7c 24 ?? 31 ee } 		$a_01_1 = {31 f9 c1 ca 05 00 00 89 74 24 1c } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}