rule Trojan_Win32_Emotet_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 73 0c 00 00 f7 f9 8b 45 ?? 8a 4c 15 00 30 08 40 39 9d 8c 0c 00 00 89 45 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}