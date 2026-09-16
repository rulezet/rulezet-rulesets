rule Trojan_Win32_Farfli_AB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb e9 7e f3 64 48 09 57 56 53 ff d0 08 0c e8 15 ff 00 bb db fb 5c 82 b0 4e 0f 24 0a 4c 33 89 45 af b9 dd } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}