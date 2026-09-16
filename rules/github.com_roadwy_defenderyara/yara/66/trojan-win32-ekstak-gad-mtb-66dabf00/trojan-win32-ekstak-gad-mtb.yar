rule Trojan_Win32_Ekstak_GAD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 1f d4 71 00 96 ?? ?? ?? ?? be ?? ?? ?? ?? 49 b9 ?? ?? ?? ?? 00 dc 01 00 35 34 f5 b7 00 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}