rule Trojan_Win32_Ursnif_B_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e9 5f 8b 1d ?? ?? ?? ?? 8b ee 6b ed 45 03 ef 39 1d ?? ?? ?? ?? 76 06 01 35 ?? ?? ?? ?? 8b 54 24 10 05 20 af 8e 01 a3 ?? ?? ?? ?? 89 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}