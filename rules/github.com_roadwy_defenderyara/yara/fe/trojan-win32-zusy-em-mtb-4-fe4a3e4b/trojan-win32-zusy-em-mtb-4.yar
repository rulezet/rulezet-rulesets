rule Trojan_Win32_Zusy_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 84 34 e0 00 00 00 88 94 3c e0 00 00 00 0f b6 b4 34 e0 00 00 00 03 f2 8b 7d 08 81 e6 ff 00 00 00 8b 94 24 30 02 00 00 8a 04 0f 32 84 34 e0 00 00 00 88 04 0a } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}