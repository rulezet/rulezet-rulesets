rule Trojan_Win32_Ekstak_RD_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 15 a4 80 65 00 e8 44 7b df ff e8 4f d7 da ff 68 ?? 03 00 00 e8 25 f6 ff ff 8b 15 e0 c4 65 00 03 d0 83 c4 04 89 15 e0 c4 65 00 e8 5f 00 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}