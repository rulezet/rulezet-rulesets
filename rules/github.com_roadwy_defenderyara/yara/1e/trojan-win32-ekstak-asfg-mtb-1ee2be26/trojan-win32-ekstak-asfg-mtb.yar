rule Trojan_Win32_Ekstak_ASFG_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {65 00 ff 15 ?? ?? 65 00 50 ff 15 ?? ?? 65 00 f7 d8 1b c0 f7 d8 c3 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}