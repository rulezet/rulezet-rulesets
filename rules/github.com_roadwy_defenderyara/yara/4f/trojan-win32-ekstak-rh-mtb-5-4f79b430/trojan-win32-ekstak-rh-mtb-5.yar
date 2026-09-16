rule Trojan_Win32_Ekstak_RH_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 6c 32 65 00 8b f0 ff 15 00 33 65 00 85 c0 74 1a 8d 4c 24 04 51 50 ff 15 fc 32 65 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}