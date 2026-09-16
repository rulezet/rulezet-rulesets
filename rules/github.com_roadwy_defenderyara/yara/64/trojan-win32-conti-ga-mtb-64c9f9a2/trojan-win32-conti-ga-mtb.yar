rule Trojan_Win32_Conti_GA_MTB{
	meta:
		description = "Trojan:Win32/Conti.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 0d 00 ff ff ff 40 0f b6 80 ?? ?? ?? ?? 33 ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 88 0a 90 0a 28 00 03 c2 25 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}