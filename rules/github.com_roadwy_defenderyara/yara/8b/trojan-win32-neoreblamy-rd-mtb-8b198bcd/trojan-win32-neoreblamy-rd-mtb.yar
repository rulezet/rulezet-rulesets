rule Trojan_Win32_Neoreblamy_RD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 f8 33 45 dc 99 89 85 58 ff ff ff 89 95 5c ff ff ff ff b5 5c ff ff ff ff b5 58 ff ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}