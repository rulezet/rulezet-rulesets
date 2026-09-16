rule Trojan_Win32_Dridex_NA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_81_0 = {30 74 36 2d 2b 43 2a 50 64 32 2b 57 6b 21 65 2b 2d 2e 70 64 62 } 	condition:
		((#a_81_0  & 1)*10) >=10
 
}