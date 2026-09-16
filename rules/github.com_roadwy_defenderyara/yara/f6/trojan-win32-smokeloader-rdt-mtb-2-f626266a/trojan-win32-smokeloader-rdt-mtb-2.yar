rule Trojan_Win32_SmokeLoader_RDT_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 fa fe ff ff 30 04 33 83 ff 0f 75 21 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}