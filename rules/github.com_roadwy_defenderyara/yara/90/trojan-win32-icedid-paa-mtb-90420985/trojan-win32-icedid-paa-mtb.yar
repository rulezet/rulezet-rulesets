rule Trojan_Win32_IcedID_PAA_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 10 8b 54 24 10 0f b6 c3 0f b6 da 0f af d8 8b 15 ?? ?? ?? ?? c0 e3 05 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}