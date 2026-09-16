rule Trojan_Win32_Copak_GMC_MTB{
	meta:
		description = "Trojan:Win32/Copak.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 31 4a ba f3 5b 16 11 41 21 d2 81 c0 ?? ?? ?? ?? 39 d9 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}