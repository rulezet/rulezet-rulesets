rule Trojan_Win32_Emotet_DE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 ff 74 27 29 c9 49 23 0a 83 c2 04 83 c1 ee 31 d9 8d 49 ff 89 cb 89 4e 00 83 ef 04 83 ee fc c7 05 [0-04] 07 1a 40 00 eb } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}