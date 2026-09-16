rule Trojan_Win32_Ekstak_RG_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {dc 05 58 e0 65 00 dd 1d 58 e0 65 00 ff 15 a4 b4 65 00 68 64 e0 65 00 ff 15 88 b4 65 00 50 ff 15 84 b4 65 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}