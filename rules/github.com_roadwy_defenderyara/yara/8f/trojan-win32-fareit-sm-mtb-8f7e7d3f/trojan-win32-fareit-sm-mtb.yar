rule Trojan_Win32_Fareit_SM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 10 83 c1 ?? 73 90 09 09 00 8a 91 ?? ?? ?? ?? 80 f2 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}