rule Trojan_Win32_Emotet_AD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 f6 2b 30 f7 de 83 c0 ?? 83 ee ?? 01 fe 83 c6 ?? 8d 3e c7 01 00 00 00 00 09 31 83 c1 04 83 c3 04 81 fb ?? ?? ?? ?? 75 ?? 59 ff 35 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}