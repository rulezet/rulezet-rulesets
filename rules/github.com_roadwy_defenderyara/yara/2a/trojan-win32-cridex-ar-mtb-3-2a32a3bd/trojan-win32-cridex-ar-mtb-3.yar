rule Trojan_Win32_Cridex_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 f8 d1 5f 01 00 0f b6 05 ?? ?? ?? ?? 8d 0c 51 81 c1 a4 c1 fe ff 03 ce 89 0d ?? ?? ?? ?? 3b c7 77 11 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}