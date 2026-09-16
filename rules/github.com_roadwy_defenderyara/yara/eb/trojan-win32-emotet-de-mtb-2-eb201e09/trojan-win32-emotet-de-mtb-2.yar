rule Trojan_Win32_Emotet_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 f1 83 c6 01 8b ca 8b 54 24 14 8a 44 32 ff 8b d1 2b d3 0f b6 14 3a 88 54 2e ff } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}