rule Trojan_Win32_Emotet_MX_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 ff 03 00 00 f7 f9 8b 44 24 ?? 8b 4c 24 ?? 40 89 44 24 ?? 8a 54 14 ?? 30 54 01 ff 8d 4c 24 ?? c7 84 24 3c 04 00 00 ff ff ff ff e8 ?? ?? ?? ?? 39 ac 24 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}