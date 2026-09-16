rule Trojan_Win32_Emotet_BS_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 75 26 00 00 99 f7 f9 8b 45 ?? 8a 08 8a 94 15 ?? ?? ?? ?? 32 ca 88 08 40 89 45 ?? 8b 45 ?? 48 89 45 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}