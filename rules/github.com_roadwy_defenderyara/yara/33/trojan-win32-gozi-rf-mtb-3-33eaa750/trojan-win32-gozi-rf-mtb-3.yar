rule Trojan_Win32_Gozi_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 fe ff ff 0f b6 ?? 8b 85 04 fe ff ff 99 be ?? 00 00 00 f7 fe 8b 85 64 fe ff ff 0f b6 14 10 33 ca 8b 85 ?? fe ff ff 03 85 ?? fe ff ff 88 08 eb aa } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}