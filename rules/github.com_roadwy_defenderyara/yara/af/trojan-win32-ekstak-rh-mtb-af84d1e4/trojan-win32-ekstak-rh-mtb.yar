rule Trojan_Win32_Ekstak_RH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec a1 f0 d4 46 00 ff 75 14 ff d0 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}