rule Trojan_Win32_Emotet_BS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 fb 89 55 ?? 03 d7 52 51 e8 ?? ?? ?? ?? 8b 45 ?? 40 3b c6 59 59 89 45 ?? 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}