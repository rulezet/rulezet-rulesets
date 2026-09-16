rule Trojan_Win32_Qukart_GZF_MTB_2{
	meta:
		description = "Trojan:Win32/Qukart.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 02 85 8b 79 6a a0 8b cf ?? ?? 65 56 81 74 04 ?? 81 68 45 52 ?? ?? 52 c5 a8 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}