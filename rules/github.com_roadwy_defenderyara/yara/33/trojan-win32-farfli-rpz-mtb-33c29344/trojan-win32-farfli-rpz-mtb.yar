rule Trojan_Win32_Farfli_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 10 8b 40 10 33 ff 03 c2 33 d2 8b c8 2b ce 3b f0 0f 47 ca 89 4d 0c 85 c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}