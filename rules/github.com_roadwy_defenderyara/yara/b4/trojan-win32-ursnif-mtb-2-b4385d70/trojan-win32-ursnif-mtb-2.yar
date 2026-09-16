rule Trojan_Win32_Ursnif_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 ce 83 e6 03 75 0a 89 fb 66 01 da c1 ca 03 89 d7 30 10 40 c1 ca 08 e2 e7 e9 ?? ?? 00 00 90 0a 4f 00 e8 00 00 00 00 5b 8d 43 ?? bf } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}