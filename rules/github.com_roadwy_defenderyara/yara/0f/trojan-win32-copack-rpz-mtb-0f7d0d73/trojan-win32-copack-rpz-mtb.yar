rule Trojan_Win32_Copack_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Copack.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c3 81 ee 01 00 00 00 8d 14 13 4e 21 f6 01 c9 8b 12 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}