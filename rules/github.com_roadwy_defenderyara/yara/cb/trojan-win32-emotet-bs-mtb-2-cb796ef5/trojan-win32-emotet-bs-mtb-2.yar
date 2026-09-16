rule Trojan_Win32_Emotet_BS_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fb 8b 45 ?? 0f b6 14 10 8b 45 ?? 0f be 1c 08 89 d8 21 d0 09 da 8b 5d ?? f7 d0 21 d0 88 04 0b 41 eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}