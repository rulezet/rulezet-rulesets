rule Trojan_Win32_Chapak_EAFR_MTB{
	meta:
		description = "Trojan:Win32/Chapak.EAFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 84 01 e1 bf 01 00 8b 15 ?? ?? ?? ?? 88 04 11 41 3b 0d } 	condition:
		((#a_02_0  & 1)*5) >=5
 
}