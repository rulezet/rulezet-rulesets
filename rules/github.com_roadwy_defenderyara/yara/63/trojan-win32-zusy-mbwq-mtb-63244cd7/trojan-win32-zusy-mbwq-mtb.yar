rule Trojan_Win32_Zusy_MBWQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 58 53 56 57 89 65 e8 ff 15 ?? 83 63 00 33 d2 8a d4 89 15 44 0d 64 00 8b c8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}