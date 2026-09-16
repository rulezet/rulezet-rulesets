rule Trojan_Win32_Ekstak_RG_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 33 c0 80 e2 3f 8a c2 0d c0 ff 00 00 83 c4 0c c3 90 90 90 90 55 8b ec 8b 45 14 50 e8 4a 98 20 00 e8 7f ff ff ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}