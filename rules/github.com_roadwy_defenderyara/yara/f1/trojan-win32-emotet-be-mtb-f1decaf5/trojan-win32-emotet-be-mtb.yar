rule Trojan_Win32_Emotet_BE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a d0 8a cb f6 d1 0a d8 8b 44 24 ?? f6 d2 0a ca 22 cb 88 08 40 83 6c 24 ?? 01 89 44 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}