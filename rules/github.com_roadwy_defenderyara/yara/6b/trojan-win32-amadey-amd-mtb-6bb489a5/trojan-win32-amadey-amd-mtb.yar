rule Trojan_Win32_Amadey_AMD_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 8d 4d e8 51 50 56 ff 75 b4 ff d3 8d 45 ec 50 ff 75 ec 56 57 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}