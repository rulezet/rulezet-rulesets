rule Trojan_Win32_Remcos_ACH_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 07 8b 07 31 05 ?? ?? ?? ?? a1 90 1b 00 31 07 6a 04 68 00 10 00 00 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}