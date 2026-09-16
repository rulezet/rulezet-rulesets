rule Trojan_Win32_GCleaner_AGC_MTB_2{
	meta:
		description = "Trojan:Win32/GCleaner.AGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 01 0f 43 45 bc 6a 00 6a 03 ff 73 40 ff 73 3c 6a 50 50 56 ff 15 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}