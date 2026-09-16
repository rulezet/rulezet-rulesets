rule Trojan_Win32_Zusy_B_MTB{
	meta:
		description = "Trojan:Win32/Zusy.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 02 8b 56 10 8a 0c b8 2a cb 88 4d f0 3b 56 14 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}