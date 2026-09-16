rule Trojan_Win32_Ekstak_RB_MTB_4{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 68 54 4f 65 00 e8 92 63 fb ff 8b 45 08 83 c4 04 68 54 4f 65 00 50 e8 b1 64 fb ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}