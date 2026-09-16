rule Trojan_Win32_Ekstak_RG_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e0 46 00 ff d0 68 30 10 47 00 68 d4 1a 47 00 ff 15 ?? e0 46 00 e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}