rule Trojan_Win32_Ekstak_RG_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 e9 a4 65 00 8b f0 e8 9b ff ff ff 8b 7d 14 83 c4 04 85 f6 74 0b 8d 55 fc 52 57 ff 15 50 43 65 00 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}