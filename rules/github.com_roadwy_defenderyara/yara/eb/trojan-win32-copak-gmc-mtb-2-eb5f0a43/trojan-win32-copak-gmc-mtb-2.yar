rule Trojan_Win32_Copak_GMC_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5f 48 29 d0 09 c2 e8 ?? ?? ?? ?? 21 d2 29 d0 21 c2 31 3e } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}