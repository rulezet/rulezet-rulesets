rule Trojan_Win32_Ursnif_PB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 f8 8a 00 88 45 ?? 8b 45 fc 03 45 f8 8b 4d f0 03 4d f8 8b 55 f0 8a 04 02 88 01 8b 45 fc 03 45 f8 8b 4d f0 8a 55 f7 88 14 01 eb c1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}