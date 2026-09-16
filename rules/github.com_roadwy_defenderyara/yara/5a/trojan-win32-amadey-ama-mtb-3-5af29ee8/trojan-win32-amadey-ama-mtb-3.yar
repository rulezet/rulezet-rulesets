rule Trojan_Win32_Amadey_AMA_MTB_3{
	meta:
		description = "Trojan:Win32/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 85 ec f7 ff ff 68 c0 ea ?? 00 50 ff 15 ?? ?? ?? ?? 83 c4 10 8d 85 ec f7 ff ff 6a 00 68 00 00 00 84 6a 00 6a 00 50 57 ff 15 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}