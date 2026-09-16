rule Trojan_Win32_Stealc_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 0c 6a 00 6a 00 6a 00 6a 00 ff d6 ff d7 4b 75 e8 b9 73 00 00 00 ba 6d 00 00 00 66 89 0d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}