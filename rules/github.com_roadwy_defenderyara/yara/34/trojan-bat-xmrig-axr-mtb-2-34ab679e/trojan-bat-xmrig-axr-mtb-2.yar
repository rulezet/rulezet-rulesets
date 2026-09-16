rule Trojan_BAT_Xmrig_AXR_MTB_2{
	meta:
		description = "Trojan:BAT/Xmrig.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 5b 00 00 70 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 73 05 00 00 0a 0d 09 08 6f ?? 00 00 0a 17 73 07 00 00 0a 13 04 11 04 7e 01 00 00 04 16 7e 01 00 00 04 8e 69 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}