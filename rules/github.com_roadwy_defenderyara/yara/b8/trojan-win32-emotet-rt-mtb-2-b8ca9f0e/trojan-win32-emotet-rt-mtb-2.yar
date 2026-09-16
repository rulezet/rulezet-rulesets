rule Trojan_Win32_Emotet_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f0 0f b6 44 24 ?? 57 99 bf ab 05 00 00 f7 ff 80 c2 3d 85 f6 76 ?? 8a 01 32 c2 02 c2 88 01 41 83 ee 01 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}