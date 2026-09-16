rule Trojan_Win32_Farfli_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 fe 29 ff 8d 04 02 8b 00 81 c7 01 00 00 00 81 e0 ff 00 00 00 81 c2 01 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}