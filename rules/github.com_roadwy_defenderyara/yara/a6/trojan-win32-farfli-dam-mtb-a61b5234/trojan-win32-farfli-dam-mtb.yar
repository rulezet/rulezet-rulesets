rule Trojan_Win32_Farfli_DAM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 32 c2 02 c2 88 01 41 83 ee 01 75 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}