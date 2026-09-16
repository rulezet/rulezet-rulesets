rule Trojan_Win32_Amadey_A_MTB{
	meta:
		description = "Trojan:Win32/Amadey.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 4d f4 51 50 56 ff 75 f0 ff d3 8d 45 f8 50 ff 75 f8 56 57 ff 15 ?? ?? ?? ?? 85 c0 75 d9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}