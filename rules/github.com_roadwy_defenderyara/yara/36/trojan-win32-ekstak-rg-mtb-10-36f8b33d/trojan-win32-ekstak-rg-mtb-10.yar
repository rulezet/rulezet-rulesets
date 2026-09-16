rule Trojan_Win32_Ekstak_RG_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 00 40 65 00 68 44 70 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 a8 42 65 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}