rule Trojan_Win32_Emotet_RTA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b c9 03 0f af d7 03 d3 03 d0 8b 44 24 ?? 8a 0c 11 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}