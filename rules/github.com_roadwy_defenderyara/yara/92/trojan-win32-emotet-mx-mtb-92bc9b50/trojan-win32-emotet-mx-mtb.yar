rule Trojan_Win32_Emotet_MX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 8f 02 00 00 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 43 4d 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}