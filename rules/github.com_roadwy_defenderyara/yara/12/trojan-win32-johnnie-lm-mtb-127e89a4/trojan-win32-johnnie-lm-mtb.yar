rule Trojan_Win32_Johnnie_LM_MTB{
	meta:
		description = "Trojan:Win32/Johnnie.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 9b 00 00 00 00 8a 91 ?? ?? ?? ?? 30 ?? ?? ?? ?? ?? 83 f9 ?? 75 ?? 33 c9 eb ?? 41 40 3b c6 72 ?? 8b 45 fc ff ?? 6a 00 ff } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}