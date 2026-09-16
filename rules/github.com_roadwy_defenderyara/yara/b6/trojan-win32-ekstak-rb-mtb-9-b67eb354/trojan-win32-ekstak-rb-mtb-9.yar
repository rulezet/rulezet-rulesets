rule Trojan_Win32_Ekstak_RB_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 ec 04 01 00 00 56 57 b9 41 00 00 00 33 c0 8d bd fc fe ff ff f3 ab 8b 45 10 8d 8d fc fe ff ff 50 51 ff 15 60 40 4b 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}