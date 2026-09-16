rule Trojan_Win32_Guloader_RR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 30 30 ff 2f 2f 2f fe 30 30 30 ff 1d 49 76 ff 1a 4c 7d fe 2f 30 31 ff 2f 2f 2f fe 30 30 30 ff 2f 2f 2f fe 30 30 30 ee 2d 32 37 5c 00 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}