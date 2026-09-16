rule Trojan_Win32_Stelega_RW_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 09 ff e8 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 29 f8 31 0b 01 f8 09 c7 43 81 c0 12 6c ea ad } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}