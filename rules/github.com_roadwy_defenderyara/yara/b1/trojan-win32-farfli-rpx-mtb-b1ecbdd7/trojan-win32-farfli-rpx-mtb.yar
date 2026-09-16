rule Trojan_Win32_Farfli_RPX_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 c9 01 ff 8d 14 02 8b 12 81 e2 ff 00 00 00 81 c0 01 00 00 00 09 f9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}