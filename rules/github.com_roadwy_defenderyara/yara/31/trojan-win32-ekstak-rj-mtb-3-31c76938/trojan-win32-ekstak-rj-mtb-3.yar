rule Trojan_Win32_Ekstak_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6c 4c 00 ff 15 ?? f3 4b 00 6a 4e ff 15 ?? f5 4b 00 6a 00 ff 15 ?? f3 4b 00 8b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}