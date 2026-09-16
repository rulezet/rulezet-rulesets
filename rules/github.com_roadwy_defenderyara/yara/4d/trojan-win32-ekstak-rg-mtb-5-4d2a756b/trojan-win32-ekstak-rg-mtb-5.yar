rule Trojan_Win32_Ekstak_RG_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 e8 e7 ca f6 ff 68 38 b9 85 00 6a 00 ff 15 98 44 65 00 50 e8 d4 fe ff ff 31 05 78 ac 65 00 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}